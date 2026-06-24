mod common;

use brokk_bifrost::{Language, SearchToolsService};
use common::InlineTestProject;
use serde_json::{Value, json};
use std::sync::{LazyLock, Mutex};

static LOOKUP_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn lookup(root: &std::path::Path, args: &str) -> Value {
    let _guard = LOOKUP_LOCK.lock().expect("lookup lock poisoned");
    let service = SearchToolsService::new_manual_without_semantic_index(root.to_path_buf())
        .expect("failed to build searchtools service");
    let payload = service
        .call_tool_json("get_definition_by_location", args)
        .expect("get_definition_by_location call failed");
    serde_json::from_str(&payload).expect("get_definition_by_location returned invalid JSON")
}

fn lookup_reference(root: &std::path::Path, args: &str) -> Value {
    let _guard = LOOKUP_LOCK.lock().expect("lookup lock poisoned");
    let service = SearchToolsService::new_manual_without_semantic_index(root.to_path_buf())
        .expect("failed to build searchtools service");
    let payload = service
        .call_tool_json("get_definition_by_reference", args)
        .expect("get_definition_by_reference call failed");
    serde_json::from_str(&payload).expect("get_definition_by_reference returned invalid JSON")
}

fn column_of(line: &str, needle: &str) -> usize {
    line.find(needle).expect("needle in line") + 1
}

fn character_column_of(line: &str, needle: &str) -> usize {
    line[..line.find(needle).expect("needle in line")]
        .chars()
        .count()
        + 1
}

#[test]
fn rust_named_import_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod util;
use crate::util::format_value;

pub fn run() {
    format_value();
}
"#,
        )
        .file(
            "util.rs",
            r#"
pub fn format_value() {}
"#,
        )
        .build();

    let line = "    format_value();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "format_value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["reference"]["target"], "format_value", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "format_value", "{value}");
    assert_eq!(result["definitions"][0]["path"], "util.rs", "{value}");
}

#[test]
fn rust_grouped_crate_import_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", "pub mod env;\n")
        .file("src/env.rs", "pub fn env_init() {}\n")
        .file(
            "src/bin/app.rs",
            r#"
use app::{
    env::{env_init},
};

fn main() {
    env_init();
}
"#,
        )
        .build();

    let line = "    env_init();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/bin/app.rs","line":7,"column":{}}}]}}"#,
            column_of(line, "env_init")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "src/env.rs", "{value}");
}

#[test]
fn rust_glob_import_resolves_public_export_to_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "mod service;\n")
        .file("service.rs", "pub struct Foo;\n")
        .file(
            "main.rs",
            r#"
mod service;
use crate::service::*;

fn run() {
    let _ = Foo {};
}
"#,
        )
        .build();

    let line = "    let _ = Foo {};";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "Foo")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "service.rs", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Foo", "{value}");
}

#[test]
fn rust_glob_import_does_not_resolve_private_name() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("service.rs", "struct Hidden;\n")
        .file(
            "main.rs",
            r#"
mod service;
use crate::service::*;

fn run() {
    let _ = Hidden {};
}
"#,
        )
        .build();

    let line = "    let _ = Hidden {};";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "Hidden")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_glob_reexport_resolves_to_original_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("service.rs", "pub struct Foo;\n")
        .file("index.rs", "pub use crate::service::*;\n")
        .file(
            "main.rs",
            r#"
mod service;
mod index;
use crate::index::Foo;

fn run() {
    let _ = Foo {};
}
"#,
        )
        .build();

    let line = "    let _ = Foo {};";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":7,"column":{}}}]}}"#,
            column_of(line, "Foo")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "service.rs", "{value}");
}

#[test]
fn rust_local_binding_shadows_glob_imported_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("service.rs", "pub struct Foo;\n")
        .file(
            "main.rs",
            r#"
mod service;
use crate::service::*;

fn run() {
    let Foo = ();
    let _ = Foo;
}
"#,
        )
        .build();

    let line = "    let _ = Foo;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":7,"column":{}}}]}}"#,
            column_of(line, "Foo")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_explicit_import_takes_precedence_over_glob_import() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "main.rs",
            r#"
mod private_mod {
    pub struct Foo;
}
mod public_mod {
    pub struct Foo;
}
use crate::private_mod::Foo;
use crate::public_mod::*;

fn run() {
    let _ = Foo {};
}
"#,
        )
        .build();

    let line = "    let _ = Foo {};";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":12,"column":{}}}]}}"#,
            column_of(line, "Foo")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["fqn"], "private_mod.Foo",
        "{value}"
    );
}

#[test]
fn rust_struct_pattern_type_name_does_not_shadow_glob_import() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("service.rs", "pub struct Foo { pub value: i32 }\n")
        .file(
            "main.rs",
            r#"
mod service;
use crate::service::*;

fn input() -> Foo {
    todo!()
}

fn run() {
    let Foo { value } = input();
}
"#,
        )
        .build();

    let line = "    let Foo { value } = input();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":10,"column":{}}}]}}"#,
            column_of(line, "Foo")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "service.rs", "{value}");
}

#[test]
fn rust_local_item_shadows_glob_imported_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("service.rs", "pub struct Foo;\n")
        .file(
            "main.rs",
            r#"
mod service;
use crate::service::*;

fn run() {
    struct Foo;
    let _ = Foo {};
}
"#,
        )
        .build();

    let line = "    let _ = Foo {};";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":7,"column":{}}}]}}"#,
            column_of(line, "Foo")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_let_binding_does_not_shadow_own_initializer() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("service.rs", "pub struct Foo;\n")
        .file(
            "main.rs",
            r#"
mod service;
use crate::service::*;

fn run() {
    let Foo = Foo {};
}
"#,
        )
        .build();

    let line = "    let Foo = Foo {};";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "= Foo") + 2
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "service.rs", "{value}");
}

#[test]
fn rust_inner_block_binding_does_not_shadow_after_block() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("service.rs", "pub struct Foo;\n")
        .file(
            "main.rs",
            r#"
mod service;
use crate::service::*;

fn run() {
    {
        let Foo = ();
    }
    let _ = Foo {};
}
"#,
        )
        .build();

    let line = "    let _ = Foo {};";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":9,"column":{}}}]}}"#,
            column_of(line, "Foo")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "service.rs", "{value}");
}

#[test]
fn rust_later_local_item_shadows_glob_imported_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("service.rs", "pub struct Foo;\n")
        .file(
            "main.rs",
            r#"
mod service;
use crate::service::*;

fn run() {
    let _ = Foo {};
    struct Foo;
}
"#,
        )
        .build();

    let line = "    let _ = Foo {};";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "Foo")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_tuple_struct_pattern_binding_shadows_glob_imported_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("service.rs", "pub struct Foo;\n")
        .file(
            "main.rs",
            r#"
mod service;
use crate::service::*;

struct Pair<T>(T);

fn input() -> Pair<()> {
    todo!()
}

fn run() {
    let Pair(Foo) = input();
    let _ = Foo;
}
"#,
        )
        .build();

    let line = "    let _ = Foo;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":13,"column":{}}}]}}"#,
            column_of(line, "Foo")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_reference_context_resolves_target_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod util;
use crate::util::helper;

pub fn run() {
    let value = helper();
}
"#,
        )
        .file("util.rs", "pub fn helper() {}\n")
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "run",
                "context": "let value = helper();",
                "target": "helper"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert!(
        result.as_object().unwrap().get("reference").is_none(),
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "util.rs", "{value}");
}

#[test]
fn rust_struct_field_access_resolves_from_parameters_and_result_locals() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
struct BridgeContext {
    settings: SettingsStore,
}

struct SettingsStore {
    path: String,
}

struct RolloutRewrite {
    session_meta_count: usize,
}

fn build() -> anyhow::Result<RolloutRewrite> {
    todo!()
}

fn run(ctx: BridgeContext) -> anyhow::Result<()> {
    let rewrite = build()?;
    let _ = ctx.settings.path;
    let _ = rewrite.session_meta_count;
    Ok(())
}
"#,
        )
        .build();

    let settings_line = "    let _ = ctx.settings.path;";
    let settings = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":20,"column":{}}}]}}"#,
            column_of(settings_line, "settings")
        ),
    );
    assert_eq!(settings["results"][0]["status"], "resolved", "{settings}");
    assert_eq!(
        settings["results"][0]["definitions"][0]["fqn"], "BridgeContext.settings",
        "{settings}"
    );

    let session_line = "    let _ = rewrite.session_meta_count;";
    let session_meta_count = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":21,"column":{}}}]}}"#,
            column_of(session_line, "session_meta_count")
        ),
    );
    assert_eq!(
        session_meta_count["results"][0]["status"], "resolved",
        "{session_meta_count}"
    );
    assert_eq!(
        session_meta_count["results"][0]["definitions"][0]["fqn"],
        "RolloutRewrite.session_meta_count",
        "{session_meta_count}"
    );
}

#[test]
fn rust_struct_field_access_ignores_shadowing_binding_after_inner_scope() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
struct Outer {
    name: String,
}

struct Inner {
    name: String,
}

fn run(value: Outer) {
    {
        let value: Inner = todo!();
        let _ = value.name;
    }
    let _ = value.name;
}
"#,
        )
        .build();

    let line = "    let _ = value.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":15,"column":{}}}]}}"#,
            column_of(line, "name")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "Outer.name",
        "{value}"
    );
}

#[test]
fn rust_unimported_inline_module_type_does_not_guess_same_file_identifier() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod hidden {
    pub struct Hidden {
        pub name: String,
    }
}

fn run(value: Hidden) {
    let _ = value.name;
}
"#,
        )
        .build();

    let line = "    let _ = value.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":9,"column":{}}}]}}"#,
            column_of(line, "name")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_function_local_use_does_not_leak_to_sibling_function_type_lookup() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
mod hidden {
    pub struct Hidden {
        pub name: String,
    }
}

fn other() {
    use crate::hidden::Hidden;
}

fn run(value: Hidden) {
    let _ = value.name;
}
"#,
        )
        .build();

    let line = "    let _ = value.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":13,"column":{}}}]}}"#,
            column_of(line, "name")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_parent_module_use_does_not_leak_into_inline_child_module() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
mod hidden {
    pub struct Hidden {
        pub name: String,
    }
}

use crate::hidden::Hidden;

mod child {
    fn run(value: Hidden) {
        let _ = value.name;
    }
}
"#,
        )
        .build();

    let line = "        let _ = value.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":12,"column":{}}}]}}"#,
            column_of(line, "name")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_function_local_use_does_not_leak_through_resolve_bare_for_crate_root_type() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
pub struct Actual {
    pub name: String,
}

fn other() {
    use crate::Actual as Hidden;
}

fn run(value: Hidden) {
    let _ = value.name;
}
"#,
        )
        .build();

    let line = "    let _ = value.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":11,"column":{}}}]}}"#,
            column_of(line, "name")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_inline_module_local_type_resolves_inside_same_module_scope() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
mod child {
    struct Local {
        name: String,
    }

    fn run(value: Local) {
        let _ = value.name;
    }
}
"#,
        )
        .build();

    let line = "        let _ = value.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":8,"column":{}}}]}}"#,
            column_of(line, "name")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "child.Local.name",
        "{value}"
    );
}

#[test]
fn rust_inline_module_local_type_resolves_before_later_declaration() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
mod child {
    fn run(value: Local) {
        let _ = value.name;
    }

    struct Local {
        name: String,
    }
}
"#,
        )
        .build();

    let line = "        let _ = value.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":4,"column":{}}}]}}"#,
            column_of(line, "name")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "child.Local.name",
        "{value}"
    );
}

#[test]
fn rust_later_module_use_resolves_earlier_same_module_reference() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
mod hidden {
    pub struct Hidden {
        pub name: String,
    }
}

fn run(value: Hidden) {
    let _ = value.name;
}

use crate::hidden::Hidden;
"#,
        )
        .build();

    let line = "    let _ = value.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":9,"column":{}}}]}}"#,
            column_of(line, "name")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "hidden.Hidden.name",
        "{value}"
    );
}

#[test]
fn rust_struct_field_access_resolves_from_option_expect_locals() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", "pub mod pricing;\npub mod route;\npub use route::RouteCheapnessEstimate;\n")
        .file("src/route.rs", "pub struct RouteCheapnessEstimate {\n    pub input_price_per_mtok_micros: Option<u64>,\n}\n")
        .file(
            "src/pricing.rs",
            r#"
use crate::{RouteCheapnessEstimate};

pub fn pricing() -> Option<RouteCheapnessEstimate> {
    todo!()
}

fn run() {
    let fast = pricing().expect("priced model");
    let _ = fast.input_price_per_mtok_micros;
}
"#,
        )
        .build();

    let line = "    let _ = fast.input_price_per_mtok_micros;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/pricing.rs","line":10,"column":{}}}]}}"#,
            column_of(line, "input_price_per_mtok_micros")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "route.RouteCheapnessEstimate.input_price_per_mtok_micros",
        "{value}"
    );
}

#[test]
fn rust_struct_field_access_resolves_from_macro_token_trees() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
macro_rules! object {
    ($($tt:tt)*) => {};
}

pub struct LlmModel {
    pub name: String,
}

pub struct ModelFit {
    pub model: LlmModel,
}

fn fit_to_json(fit: &ModelFit) {
    object!({
        "name": fit.model.name,
        "ollama_name": helper(&fit.model.name),
    });
}
"#,
        )
        .build();

    let line = r#"        "ollama_name": helper(&fit.model.name),"#;
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":17,"column":{}}}]}}"#,
            column_of(line, "model")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "ModelFit.model", "{value}");
}

#[test]
fn rust_struct_field_access_resolves_imported_parameter_types() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
pub mod display;
pub mod fit;
pub mod models;
"#,
        )
        .file(
            "src/fit.rs",
            r#"
use crate::models::LlmModel;

pub struct ModelFit {
    pub model: LlmModel,
}
"#,
        )
        .file(
            "src/models.rs",
            r#"
pub struct LlmModel {
    pub name: String,
}
"#,
        )
        .file(
            "src/display.rs",
            r#"
use crate::fit::ModelFit;

fn fit_to_json(fit: &ModelFit) {
    let _ = &fit.model.name;
}
"#,
        )
        .build();

    let line = "    let _ = &fit.model.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/display.rs","line":5,"column":{}}}]}}"#,
            column_of(line, "model")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "fit.ModelFit.model",
        "{value}"
    );
}

#[test]
fn rust_get_definition_resolves_field_type_from_ast_node() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
pub mod models;

use models::MemoryRepository;

pub struct Service {
    repository: MemoryRepository,
}
"#,
        )
        .file("src/models.rs", "pub struct MemoryRepository;\n")
        .build();

    let line = "    repository: MemoryRepository,";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":7,"column":{}}}]}}"#,
            column_of(line, "MemoryRepository")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "models.MemoryRepository",
        "{value}"
    );
}

#[test]
fn rust_get_definition_resolves_function_return_type_from_ast_node() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
pub mod models;

use models::MemoryRepository;

pub fn build() -> MemoryRepository {
    MemoryRepository
}
"#,
        )
        .file("src/models.rs", "pub struct MemoryRepository;\n")
        .build();

    let line = "pub fn build() -> MemoryRepository {";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "MemoryRepository")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "models.MemoryRepository",
        "{value}"
    );
}

#[test]
fn rust_field_access_unwraps_wrapped_type_nodes() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
pub mod models;

use models::{Error, MemoryRepository};

pub struct Service {
    maybe: Option<&'static MemoryRepository>,
    result: Result<MemoryRepository, Error>,
}

pub fn build() -> anyhow::Result<MemoryRepository> {
    MemoryRepository { name: String::new() }
}

pub fn run(service: Service) {
    let _ = service.maybe.unwrap().name;
    let _ = service.result.unwrap().name;
    let _ = build().unwrap().name;
}
"#,
        )
        .file(
            "src/models.rs",
            r#"
pub struct Error;

pub struct MemoryRepository {
    pub name: String,
}
"#,
        )
        .build();

    for (line_number, line) in [
        (16, "    let _ = service.maybe.unwrap().name;"),
        (17, "    let _ = service.result.unwrap().name;"),
        (18, "    let _ = build().unwrap().name;"),
    ] {
        let value = lookup(
            project.root(),
            &format!(
                r#"{{"references":[{{"path":"src/lib.rs","line":{line_number},"column":{}}}]}}"#,
                column_of(line, "name")
            ),
        );

        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["definitions"][0]["fqn"], "models.MemoryRepository.name",
            "{value}"
        );
    }
}

#[test]
fn rust_struct_field_access_resolves_borrowed_self_field() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
pub struct Provider {
    model: String,
}

pub struct Other {
    model: String,
}

impl Provider {
    fn model(&self) -> String {
        String::new()
    }

    fn run(&self) {
        let _ = Arc::clone(&self.model);
    }
}
"#,
        )
        .build();

    let line = "        let _ = Arc::clone(&self.model);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":16,"column":{}}}]}}"#,
            column_of(line, "model")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Provider.model", "{value}");
}

#[test]
fn go_selector_chain_resolves_promoted_embedded_fields_and_range_elements() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n\ngo 1.22\n")
        .file(
            "types/types.go",
            r#"
package types

type Category struct {
    ID string
}

type ScanResult struct {
    Category Category
}
"#,
        )
        .file(
            "tui/model.go",
            r#"
package tui

import "example.com/app/types"

type dataState struct {
    results []*types.ScanResult
}

type selectionState struct {
    selected map[string]bool
}

type Model struct {
    dataState
    selectionState
}

func (m *Model) Handle() {
    for _, r := range m.results {
        if m.selected[r.Category.ID] {
            _ = r
        }
    }
    r := m.results[0]
    _ = r.Category.ID
}
"#,
        )
        .build();

    let selected_line = "        if m.selected[r.Category.ID] {";
    let selected = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"tui/model.go","line":21,"column":{}}}]}}"#,
            column_of(selected_line, "selected")
        ),
    );
    assert_eq!(selected["results"][0]["status"], "resolved", "{selected}");
    assert_eq!(
        selected["results"][0]["definitions"][0]["fqn"],
        "example.com/app/tui.selectionState.selected",
        "{selected}"
    );

    let id = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"tui/model.go","line":21,"column":{}}}]}}"#,
            column_of(selected_line, "ID")
        ),
    );
    assert_eq!(id["results"][0]["status"], "resolved", "{id}");
    assert_eq!(
        id["results"][0]["definitions"][0]["fqn"], "example.com/app/types.Category.ID",
        "{id}"
    );

    let indexed_line = "    _ = r.Category.ID";
    let indexed_id = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"tui/model.go","line":26,"column":{}}}]}}"#,
            column_of(indexed_line, "ID")
        ),
    );
    assert_eq!(
        indexed_id["results"][0]["status"], "resolved",
        "{indexed_id}"
    );
    assert_eq!(
        indexed_id["results"][0]["definitions"][0]["fqn"], "example.com/app/types.Category.ID",
        "{indexed_id}"
    );
}

#[test]
fn go_imported_package_var_resolves_inside_longer_selector_chain() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n\ngo 1.22\n")
        .file(
            "pkg/assets/assets.go",
            r#"
package assets

type FS struct{}

var Rewrites FS
"#,
        )
        .file(
            "service/rewrite.go",
            r#"
package service

import "example.com/app/pkg/assets"

func run() {
    _, _ = assets.Rewrites.ReadFile("rewrite/default.conf")
}
"#,
        )
        .build();

    let line = r#"    _, _ = assets.Rewrites.ReadFile("rewrite/default.conf")"#;
    let rewrites = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"service/rewrite.go","line":7,"column":{}}}]}}"#,
            column_of(line, "Rewrites")
        ),
    );
    assert_eq!(rewrites["results"][0]["status"], "resolved", "{rewrites}");
    assert_eq!(
        rewrites["results"][0]["definitions"][0]["fqn"],
        "example.com/app/pkg/assets._module_.Rewrites",
        "{rewrites}"
    );

    let read_file = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"service/rewrite.go","line":7,"column":{}}}]}}"#,
            column_of(line, "ReadFile")
        ),
    );
    assert_eq!(
        read_file["results"][0]["status"], "no_definition",
        "{read_file}"
    );
}

#[test]
fn python_class_and_instance_attributes_resolve_to_definitions() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "util.py",
            r#"
class ModelParser:
    @staticmethod
    def from_model(path):
        return ModelParser()
"#,
        )
        .file(
            "main.py",
            r#"
from util import ModelParser

class DataType:
    FLOAT = object()

class Service:
    def __init__(self, memory):
        self.memory = memory

    def run(self):
        return self.memory

def class_attr():
    return DataType.FLOAT

def imported_static():
    return ModelParser.from_model("model.xml")
"#,
        )
        .build();

    let class_attr = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "class_attr",
                "context": "return DataType.FLOAT",
                "target": "FLOAT"
            }]
        })
        .to_string(),
    );
    assert_eq!(
        class_attr["results"][0]["status"], "resolved",
        "{class_attr}"
    );
    assert_eq!(
        class_attr["results"][0]["definitions"][0]["fqn"], "main.DataType.FLOAT",
        "{class_attr}"
    );

    let instance_attr = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "Service.run",
                "context": "return self.memory",
                "target": "memory"
            }]
        })
        .to_string(),
    );
    assert_eq!(
        instance_attr["results"][0]["status"], "resolved",
        "{instance_attr}"
    );
    assert_eq!(
        instance_attr["results"][0]["definitions"][0]["fqn"], "main.Service.memory",
        "{instance_attr}"
    );

    let imported_static = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "imported_static",
                "context": "return ModelParser.from_model(\"model.xml\")",
                "target": "from_model"
            }]
        })
        .to_string(),
    );
    assert_eq!(
        imported_static["results"][0]["status"], "resolved",
        "{imported_static}"
    );
    assert_eq!(
        imported_static["results"][0]["definitions"][0]["fqn"], "util.ModelParser.from_model",
        "{imported_static}"
    );
}

#[test]
fn python_nested_function_self_assignment_does_not_create_outer_field() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "main.py",
            r#"
class Service:
    def configure(self):
        def inner():
            self.shadow = 1

    def read(self):
        return self.shadow
"#,
        )
        .build();

    let line = "        return self.shadow";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.py","line":8,"column":{}}}]}}"#,
            column_of(line, "shadow")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn python_nested_class_self_assignment_does_not_create_outer_field() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "main.py",
            r#"
class Service:
    def configure(self):
        class Inner:
            def run(self):
                self.shadow = 1

    def read(self):
        return self.shadow
"#,
        )
        .build();

    let line = "        return self.shadow";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.py","line":9,"column":{}}}]}}"#,
            column_of(line, "shadow")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_reference_context_collapses_repeated_targets_with_same_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod util;
use crate::util::helper;

pub fn run() {
    helper(); helper();
}
"#,
        )
        .file("util.rs", "pub fn helper() {}\n")
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "run",
                "context": "helper(); helper();",
                "target": "helper"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "util.rs", "{value}");
}

#[test]
fn rust_reference_context_reports_ambiguous_when_targets_resolve_differently() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod util;

fn helper() {}

pub fn run() {
    crate::util::helper(); helper();
}
"#,
        )
        .file("util.rs", "pub fn helper() {}\n")
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "run",
                "context": "crate::util::helper(); helper();",
                "target": "helper"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "ambiguous", "{value}");
    assert!(result["definitions"][0].is_null(), "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "ambiguous_reference_target",
        "{value}"
    );
}

#[test]
fn rust_crate_scoped_macro_resolves_from_nested_crate_root() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "printf/src/lib.rs",
            r#"
#[macro_export]
macro_rules! sprintf {
    ($fmt:expr) => { $fmt };
}

#[cfg(test)]
mod tests;
"#,
        )
        .file(
            "printf/src/tests.rs",
            r#"
pub fn test_crate_macros() {
    let target = crate::sprintf!("noargs1");
}
"#,
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "printf.src.test_crate_macros",
                "context": "let target = crate::sprintf!(\"noargs1\");",
                "target": "sprintf"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "printf.src.sprintf",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "printf/src/lib.rs",
        "{value}"
    );
}

#[test]
fn rust_struct_field_access_does_not_unwrap_option_without_syntax() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", "pub mod pricing;\npub mod route;\npub use route::RouteCheapnessEstimate;\n")
        .file("src/route.rs", "pub struct RouteCheapnessEstimate {\n    pub input_price_per_mtok_micros: Option<u64>,\n}\n")
        .file(
            "src/pricing.rs",
            r#"
use crate::{RouteCheapnessEstimate};

pub fn pricing() -> Option<RouteCheapnessEstimate> {
    todo!()
}

fn run() {
    let maybe = pricing();
    let _ = maybe.input_price_per_mtok_micros;
}
"#,
        )
        .build();

    let line = "    let _ = maybe.input_price_per_mtok_micros;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/pricing.rs","line":10,"column":{}}}]}}"#,
            column_of(line, "input_price_per_mtok_micros")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_crate_scoped_macro_resolves_inside_inline_module() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            r#"
pub mod inner {
    macro_rules! helper {
        () => {};
    }

    pub fn caller() {
        crate::inner::helper!();
    }
}
"#,
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "inner.caller",
                "context": "crate::inner::helper!();",
                "target": "helper"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "inner.helper", "{value}");
}

#[test]
fn line_column_uses_character_columns_not_byte_offsets() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod util;
use crate::util::helper;

pub fn run() {
    let café = helper();
}
"#,
        )
        .file("util.rs", "pub fn helper() {}\n")
        .build();

    let line = "    let café = helper();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":6,"column":{}}}]}}"#,
            character_column_of(line, "helper")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["reference"]["target"], "helper", "{value}");
    assert_eq!(result["definitions"][0]["path"], "util.rs", "{value}");
}

#[test]
fn rust_external_crate_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
pub fn run() {
    serde::Serialize::serialize;
}
"#,
        )
        .build();

    let line = "    serde::Serialize::serialize;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":3,"column":{}}}]}}"#,
            column_of(line, "Serialize")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "unresolvable_import_boundary", "{value}");
    assert!(result["definitions"][0].is_null(), "{value}");
}

#[test]
fn rust_unresolved_scoped_path_does_not_guess_by_leaf_name() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod util;

pub fn run() {
    crate::missing::helper();
}
"#,
        )
        .file("util.rs", "pub fn helper() {}\n")
        .build();

    let line = "    crate::missing::helper();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":5,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert!(value["results"][0]["definitions"][0].is_null(), "{value}");
}

#[test]
fn rust_root_super_path_does_not_resolve_to_crate_root_item() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
pub fn helper() {}

pub fn run() {
    super::helper();
}
"#,
        )
        .build();

    let line = "    super::helper();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":5,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert!(value["results"][0]["definitions"][0].is_null(), "{value}");
}

#[test]
fn rust_too_many_super_segments_do_not_resolve_to_crate_root_item() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
pub fn helper() {}

pub mod child {
    pub fn run() {
        super::super::helper();
    }
}
"#,
        )
        .build();

    let line = "        super::super::helper();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert!(value["results"][0]["definitions"][0].is_null(), "{value}");
}

#[test]
fn rust_unimported_bare_name_does_not_guess_workspace_identifier() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod util;

pub fn run() {
    helper();
}
"#,
        )
        .file("util.rs", "pub fn helper() {}\n")
        .build();

    let line = "    helper();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":5,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert!(value["results"][0]["definitions"][0].is_null(), "{value}");
}

#[test]
fn rust_unimported_parameter_type_does_not_guess_workspace_identifier() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
mod hidden;

pub fn run(value: Hidden) {
    let _ = value.name;
}
"#,
        )
        .file(
            "src/hidden.rs",
            r#"
pub struct Hidden {
    pub name: String,
}
"#,
        )
        .build();

    let line = "    let _ = value.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":5,"column":{}}}]}}"#,
            column_of(line, "name")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_reference_inside_test_file_resolves_without_include_tests_flag() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "tests/helper.rs",
            r##"
fn helper() {}

#[test]
pub fn run() {
    helper();
}
"##,
        )
        .build();

    let line = "    helper();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"tests/helper.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["path"], "tests/helper.rs",
        "{value}"
    );
}

#[test]
fn invalid_utf8_byte_range_returns_diagnostic_instead_of_panicking() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "pub fn helper() { let café = 1; }\n")
        .build();

    let source = std::fs::read_to_string(project.root().join("lib.rs")).expect("source");
    let start = source.find('é').expect("non-ascii byte");
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","start_byte":{},"end_byte":{}}}]}}"#,
            start + 1,
            start + 2
        ),
    );

    assert_eq!(value["results"][0]["status"], "invalid_location", "{value}");
}

#[test]
fn typescript_named_import_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("util.ts", "export function helper() {}\n")
        .file(
            "app.ts",
            r#"
import { helper } from "./util";

export function run() {
  helper();
}
"#,
        )
        .build();

    let line = "  helper();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":5,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "helper", "{value}");
    assert_eq!(result["definitions"][0]["path"], "util.ts", "{value}");
}

#[test]
fn typescript_value_reference_prefers_const_over_same_named_interface() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            r#"
export interface Widget {
  value: string;
}
export const Widget = makeWidget();

export function run() {
  consume(Widget);
}
"#,
        )
        .build();

    let line = "  consume(Widget);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":8,"column":{}}}]}}"#,
            column_of(line, "Widget")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "{value}"
    );
    assert_eq!(result["definitions"][0]["kind"], "field", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 5, "{value}");
}

#[test]
fn typescript_type_reference_prefers_interface_over_same_named_const() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            r#"
export interface Widget {
  value: string;
}
export const Widget = makeWidget();

export function run(value: Widget) {
  return value;
}
"#,
        )
        .build();

    let line = "export function run(value: Widget) {";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":7,"column":{}}}]}}"#,
            column_of(line, "Widget")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "{value}"
    );
    assert_eq!(result["definitions"][0]["kind"], "class", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 2, "{value}");
}

#[test]
fn typescript_reference_context_resolves_type_alias_union_member() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            r#"
export type ClientOptionsWithUrl = {
  accelerateUrl: string
}

export type ClientOptionsWithAdapter = {
  adapter: unknown
}

export type ClientOptions = ClientOptionsWithUrl | ClientOptionsWithAdapter
"#,
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "ClientOptions",
                "context": "export type ClientOptions = ClientOptionsWithUrl | ClientOptionsWithAdapter",
                "target": "ClientOptionsWithUrl"
            }]
        })
        .to_string(),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "app.ts.ClientOptionsWithUrl",
        "{value}"
    );
    assert_eq!(
        value["results"][0]["definitions"][0]["start_line"], 2,
        "{value}"
    );
}

#[test]
fn typescript_path_alias_import_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "tsconfig.json",
            r#"{ "compilerOptions": { "baseUrl": ".", "paths": { "~/*": ["src/*"] } } }"#,
        )
        .file("src/util.ts", "export function helper() {}\n")
        .file(
            "app.ts",
            r#"
import { helper } from "~/util";

export function run() {
  helper();
}
"#,
        )
        .build();

    let line = "  helper();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":5,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "helper", "{value}");
    assert_eq!(result["definitions"][0]["path"], "src/util.ts", "{value}");
}

#[test]
fn typescript_js_extension_import_resolves_to_ts_source() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("util.ts", "export function helper() {}\n")
        .file(
            "app.ts",
            r#"
import { helper } from "./util.js";

export function run() {
  helper();
}
"#,
        )
        .build();

    let line = "  helper();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":5,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "helper", "{value}");
    assert_eq!(result["definitions"][0]["path"], "util.ts", "{value}");
}

#[test]
fn typescript_path_alias_import_resolves_through_star_barrel() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "tsconfig.json",
            r#"{ "compilerOptions": { "baseUrl": ".", "paths": { "@renderer/*": ["src/renderer/*"] } } }"#,
        )
        .file("src/renderer/utils/index.ts", "export * from \"./naming\";\n")
        .file(
            "src/renderer/utils/naming.ts",
            "export function isEmoji(value: string): boolean { return value.length > 0; }\n",
        )
        .file(
            "src/renderer/components/UserPopup.tsx",
            r#"
import { isEmoji } from "@renderer/utils";

export function render(avatar: string) {
  return isEmoji(avatar);
}
"#,
        )
        .build();

    let line = "  return isEmoji(avatar);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/renderer/components/UserPopup.tsx","line":5,"column":{}}}]}}"#,
            column_of(line, "isEmoji")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "isEmoji", "{value}");
    assert_eq!(
        result["definitions"][0]["path"], "src/renderer/utils/naming.ts",
        "{value}"
    );
}

#[test]
fn typescript_imported_object_literal_property_resolves_through_star_barrel() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "tsconfig.json",
            r#"{ "compilerOptions": { "baseUrl": ".", "paths": { "@renderer/*": ["src/renderer/*"] } } }"#,
        )
        .file(
            "src/renderer/primitives/index.ts",
            "export * from \"./classNames\";\n",
        )
        .file(
            "src/renderer/primitives/classNames.ts",
            r#"
export const providerListClasses = {
  itemEnabledDot: 'dot',
  itemLabel: 'label'
} as const
"#,
        )
        .file(
            "src/renderer/components/ProviderListItem.tsx",
            r#"
import { providerListClasses } from "@renderer/primitives";

export function render() {
  return providerListClasses.itemEnabledDot;
}
"#,
        )
        .build();

    let line = "  return providerListClasses.itemEnabledDot;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/renderer/components/ProviderListItem.tsx","line":5,"column":{}}}]}}"#,
            column_of(line, "itemEnabledDot")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "classNames.ts.providerListClasses.itemEnabledDot",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "src/renderer/primitives/classNames.ts",
        "{value}"
    );
}

#[test]
fn typescript_destructured_typed_parameter_member_resolves_to_schema_property() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "provider.ts",
            r#"
export const ProviderSchema = z.object({
  isEnabled: z.boolean(),
})
export type Provider = z.infer<typeof ProviderSchema>
"#,
        )
        .file(
            "app.ts",
            r#"
import type { Provider } from './provider'

interface Props {
  provider: Provider
}

export function Item({ provider }: Props) {
  return provider.isEnabled
}
"#,
        )
        .build();

    let line = "  return provider.isEnabled";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":9,"column":{}}}]}}"#,
            column_of(line, "isEnabled")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "provider.ts.ProviderSchema.isEnabled",
        "{value}"
    );
}

#[test]
fn typescript_call_initialized_local_member_resolves_to_returned_object_property() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "build.ts",
            r#"
export const getBuildConfig = () => {
  return {
    visionModels: '',
  }
}

export type BuildConfig = ReturnType<typeof getBuildConfig>
"#,
        )
        .file(
            "client.ts",
            r#"
import { BuildConfig, getBuildConfig } from './build'

export function getClientConfig() {
  if (window) {
    return JSON.parse('{}') as BuildConfig
  }
  return getBuildConfig()
}
"#,
        )
        .file(
            "app.ts",
            r#"
import { getClientConfig } from './client'

export function isVisionModel() {
  const clientConfig = getClientConfig()
  return clientConfig.visionModels
}
"#,
        )
        .build();

    let line = "  return clientConfig.visionModels";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":6,"column":{}}}]}}"#,
            column_of(line, "visionModels")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "getBuildConfig.visionModels",
        "{value}"
    );
}

#[test]
fn typescript_contextual_callback_parameter_members_resolve() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "utils.ts",
            r#"
export class Response {
  setPage(): void {}
}

export class Context {
  newPage(): Page { return new Page() }
}

export class Page {
  pptrPage = ''
}

export function withContext(cb: (response: Response, context: Context) => void): void {}
"#,
        )
        .file(
            "app.ts",
            r#"
import { withContext } from './utils.js'

export function run() {
  withContext((response, context) => {
    context.newPage()
    response.setPage()
  })
}
"#,
        )
        .build();

    let context_line = "    context.newPage()";
    let context_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":6,"column":{}}}]}}"#,
            column_of(context_line, "newPage")
        ),
    );

    let context_result = &context_value["results"][0];
    assert_eq!(context_result["status"], "resolved", "{context_value}");
    assert_eq!(
        context_result["definitions"][0]["fqn"], "Context.newPage",
        "{context_value}"
    );

    let response_line = "    response.setPage()";
    let response_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":7,"column":{}}}]}}"#,
            column_of(response_line, "setPage")
        ),
    );

    let response_result = &response_value["results"][0];
    assert_eq!(response_result["status"], "resolved", "{response_value}");
    assert_eq!(
        response_result["definitions"][0]["fqn"], "Response.setPage",
        "{response_value}"
    );
}

#[test]
fn typescript_member_call_contextual_callback_parameter_members_resolve() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "utils.ts",
            r#"
export class Context {
  newPage(): Page { return new Page() }
}

export class Page {}

export function withContext(cb: (context: Context) => void): void {}
"#,
        )
        .file(
            "app.ts",
            r#"
import * as utils from './utils.js'

export function run() {
  utils.withContext(context => {
    context.newPage()
  })
}
"#,
        )
        .build();

    let line = "    context.newPage()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":6,"column":{}}}]}}"#,
            column_of(line, "newPage")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Context.newPage",
        "{value}"
    );
}

#[test]
fn typescript_awaited_member_call_initialized_local_resolves_to_return_type_member() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "utils.ts",
            r#"
export class Context {
  newPage(): Promise<Page> { return Promise.resolve(new Page()) }
}

export class Page {
  pptrPage = ''
}

export function withContext(cb: (context: Context) => Promise<void>): void {}
"#,
        )
        .file(
            "app.ts",
            r#"
import { withContext } from './utils.js'

export function run() {
  withContext(async context => {
    const page = await context.newPage()
    page.pptrPage
  })
}
"#,
        )
        .build();

    let line = "    page.pptrPage";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":7,"column":{}}}]}}"#,
            column_of(line, "pptrPage")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Page.pptrPage", "{value}");
}

#[test]
fn typescript_call_initialized_exported_object_member_resolves_to_argument_property() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "tool.ts",
            r#"
export function defineTool<T>(definition: T): T {
  return {
    ...definition,
    pageScoped: true,
  } as T
}

export const listTools = defineTool({
  handler(): void {},
})
"#,
        )
        .file(
            "app.ts",
            r#"
import { listTools } from './tool.js'

export function run() {
  listTools.handler()
}
"#,
        )
        .build();

    let line = "  listTools.handler()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":5,"column":{}}}]}}"#,
            column_of(line, "handler")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "tool.ts.listTools.handler",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["start_line"], 10, "{value}");
}

#[test]
fn typescript_call_argument_object_member_requires_shape_preserving_callee() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "tool.ts",
            r#"
export function log(definition: { handler(): void }): void {}

export const listTools = log({
  handler(): void {},
})
"#,
        )
        .file(
            "app.ts",
            r#"
import { listTools } from './tool.js'

export function run() {
  listTools.handler()
}
"#,
        )
        .build();

    let line = "  listTools.handler()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":5,"column":{}}}]}}"#,
            column_of(line, "handler")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn typescript_window_member_resolves_to_ambient_window_interface_property() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            r#"
export {}

declare global {
  interface Window {
    __dtmcp?: {
      toolGroups?: string[]
    }
  }
}

export function run() {
  if (window.__dtmcp) {}
}
"#,
        )
        .build();

    let line = "  if (window.__dtmcp) {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":13,"column":{}}}]}}"#,
            column_of(line, "__dtmcp")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Window.__dtmcp", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 6, "{value}");
}

#[test]
fn typescript_window_member_ignores_non_ambient_local_window_class() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            r#"
class Window {
  other(): void {}
}

export function run() {
  window.other()
}
"#,
        )
        .build();

    let line = "  window.other()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":7,"column":{}}}]}}"#,
            column_of(line, "other")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn javascript_destructured_commonjs_require_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "util.js",
            "function helper() {}\nexports.helper = helper;\n",
        )
        .file(
            "app.js",
            r#"
const { helper } = require("./util");

function run() {
  helper();
}
"#,
        )
        .build();

    let line = "  helper();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":5,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "util.js", "{value}");
}

#[test]
fn javascript_same_file_object_literal_property_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            r#"
const classes = {
  enabled: 'dot'
};

function render() {
  return classes.enabled;
}
"#,
        )
        .build();

    let line = "  return classes.enabled;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":7,"column":{}}}]}}"#,
            column_of(line, "enabled")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.js.classes.enabled",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["start_line"], 3, "{value}");
}

#[test]
fn javascript_member_assignment_function_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            r#"
const utils = {};
utils.typeConverter = function (value) {
  return value;
};

function render() {
  return utils.typeConverter(1);
}
"#,
        )
        .build();

    let line = "  return utils.typeConverter(1);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":8,"column":{}}}]}}"#,
            column_of(line, "typeConverter")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "utils.typeConverter",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["kind"], "function", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 3, "{value}");
}

#[test]
fn javascript_member_assignment_object_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            r#"
const alasql = {};
alasql.options = {
  csvStringToNumber: true
};

function render() {
  return alasql.options.csvStringToNumber;
}
"#,
        )
        .build();

    let line = "  return alasql.options.csvStringToNumber;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":8,"column":{}}}]}}"#,
            column_of(line, "options")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "alasql.options", "{value}");
    assert_eq!(result["definitions"][0]["kind"], "field", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 3, "{value}");
}

#[test]
fn javascript_cross_file_member_assignment_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "defs.js",
            r#"
const alasql = {};
alasql.options = {
  csvStringToNumber: true
};
"#,
        )
        .file(
            "use.js",
            r#"
function render() {
  return alasql.options.csvStringToNumber;
}
"#,
        )
        .build();

    let line = "  return alasql.options.csvStringToNumber;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"use.js","line":3,"column":{}}}]}}"#,
            column_of(line, "options")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "alasql.options", "{value}");
    assert_eq!(result["definitions"][0]["path"], "defs.js", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 3, "{value}");
}

#[test]
fn javascript_local_member_assignment_resolves_later_member_use() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            r#"
function compile(query) {
  query.windowaggrs = [];
  if (query.windowaggrs && query.windowaggrs.length > 0) {
    return query.windowaggrs;
  }
}
"#,
        )
        .build();

    let line = "  if (query.windowaggrs && query.windowaggrs.length > 0) {";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":4,"column":{}}}]}}"#,
            column_of(line, "windowaggrs")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "query.windowaggrs",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["start_line"], 3, "{value}");
}

#[test]
fn javascript_local_member_assignment_does_not_cross_function_scope() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            r#"
function compile(query) {
  query.windowaggrs = [];
}

function render(query) {
  return query.windowaggrs;
}
"#,
        )
        .build();

    let line = "  return query.windowaggrs;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":7,"column":{}}}]}}"#,
            column_of(line, "windowaggrs")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn javascript_block_shadowed_member_assignment_does_not_resolve_outer_receiver() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            r#"
function render(query, cond) {
  if (cond) {
    let query = {};
    query.windowaggrs = [];
  }
  return query.windowaggrs;
}
"#,
        )
        .build();

    let line = "  return query.windowaggrs;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":7,"column":{}}}]}}"#,
            column_of(line, "windowaggrs")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn javascript_var_receiver_assignment_remains_function_scoped_across_blocks() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            r#"
function render(cond) {
  if (cond) {
    var query = {};
    query.windowaggrs = [];
  }
  return query.windowaggrs;
}
"#,
        )
        .build();

    let line = "  return query.windowaggrs;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":7,"column":{}}}]}}"#,
            column_of(line, "windowaggrs")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "query.windowaggrs",
        "{value}"
    );
}

#[test]
fn javascript_member_expression_receiver_focus_resolves_receiver_definition() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            r#"
var re_aggrWithExpression = /^(SUM|MAX)$/;

function accepts(value) {
  return re_aggrWithExpression.test(value);
}
"#,
        )
        .build();

    let line = "  return re_aggrWithExpression.test(value);";
    let receiver_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":5,"column":{}}}]}}"#,
            column_of(line, "re_aggrWithExpression")
        ),
    );

    let result = &receiver_value["results"][0];
    assert_eq!(result["status"], "resolved", "{receiver_value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.js.re_aggrWithExpression",
        "{receiver_value}"
    );
    assert_eq!(
        result["definitions"][0]["start_line"], 2,
        "{receiver_value}"
    );

    let property_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":5,"column":{}}}]}}"#,
            column_of(line, "test")
        ),
    );
    assert_eq!(
        property_value["results"][0]["status"], "no_definition",
        "{property_value}"
    );
}

#[test]
fn javascript_unknown_receiver_member_does_not_guess_same_file_function() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            r#"
export function method() {}

export function run(obj: any) {
  obj.method();
}
"#,
        )
        .build();

    let line = "  obj.method();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":5,"column":{}}}]}}"#,
            column_of(line, "method")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn typescript_this_member_resolves_to_enclosing_class_method() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "context.ts",
            r#"
export class Context {
  private loadResource(url: string): string {
    return url
  }

  constructor() {
    const loader = (url: string) => this.loadResource(url)
  }
}
"#,
        )
        .build();

    let line = "    const loader = (url: string) => this.loadResource(url)";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"context.ts","line":8,"column":{}}}]}}"#,
            column_of(line, "loadResource")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Context.loadResource",
        "{value}"
    );
}

#[test]
fn typescript_this_member_resolves_to_enclosing_class_method_body() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "context.ts",
            r#"
export class Context {
  private validatePath(path: string): void {}

  async loadResource(path: string): Promise<string> {
    this.validatePath(path)
    return path
  }
}
"#,
        )
        .build();

    let line = "    this.validatePath(path)";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"context.ts","line":6,"column":{}}}]}}"#,
            column_of(line, "validatePath")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Context.validatePath",
        "{value}"
    );
}

#[test]
fn typescript_package_import_reports_boundary() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            r#"
import { useMemo } from "react";

export function run() {
  useMemo();
}
"#,
        )
        .build();

    let line = "  useMemo();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":5,"column":{}}}]}}"#,
            column_of(line, "useMemo")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn go_import_selector_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

import "example.com/app/sub"

func Run() {
    sub.Helper()
}
"#,
        )
        .file(
            "sub/sub.go",
            r#"
package sub

func Helper() {}
"#,
        )
        .build();

    let line = "    sub.Helper()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":7,"column":{}}}]}}"#,
            column_of(line, "Helper")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.com/app/sub.Helper",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "sub/sub.go", "{value}");
}

#[test]
fn go_import_selector_resolves_package_var_definition() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

import "errors"
import "example.com/app/store"

func Run(err error) bool {
    return errors.Is(err, store.ErrDuplicate)
}
"#,
        )
        .file(
            "store/errors.go",
            r#"
package store

import "errors"

var ErrDuplicate = errors.New("duplicate")
"#,
        )
        .build();

    let line = "    return errors.Is(err, store.ErrDuplicate)";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":8,"column":{}}}]}}"#,
            column_of(line, "ErrDuplicate")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.com/app/store._module_.ErrDuplicate",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "store/errors.go",
        "{value}"
    );
}

#[test]
fn go_external_import_selector_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

import "fmt"

func Run() {
    fmt.Println("hello")
}
"#,
        )
        .build();

    let line = r#"    fmt.Println("hello")"#;
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":7,"column":{}}}]}}"#,
            column_of(line, "Println")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn go_external_dot_import_reference_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

import . "fmt"

func Run() {
    Println("hello")
}
"#,
        )
        .build();

    let line = r#"    Println("hello")"#;
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":7,"column":{}}}]}}"#,
            column_of(line, "Println")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn go_dot_import_resolves_unqualified_definition() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

import . "example.com/app/sub"

func Run() {
    Helper()
}
"#,
        )
        .file(
            "sub/sub.go",
            r#"
package sub

func Helper() {}
"#,
        )
        .build();

    let line = "    Helper()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":7,"column":{}}}]}}"#,
            column_of(line, "Helper")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.com/app/sub.Helper",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "sub/sub.go", "{value}");
}

#[test]
fn go_receiver_field_chain_resolves_qualified_field_type() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "store/store.go",
            r#"
package store

type Client struct{}

func (c Client) Ping() {}
"#,
        )
        .file(
            "main.go",
            r#"
package main

import "example.com/app/store"

type Env struct { Client store.Client }
type Server struct { Env Env }

func (s Server) Run() {
    s.Env.Client.Ping()
}
"#,
        )
        .build();

    let line = "    s.Env.Client.Ping()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":10,"column":{}}}]}}"#,
            column_of(line, "Ping")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.com/app/store.Client.Ping",
        "{value}"
    );
}

#[test]
fn go_package_qualified_parameter_field_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "request/nginx.go",
            r#"
package request

type NginxRewriteReq struct {
    WebsiteID uint
    Name string
}
"#,
        )
        .file(
            "main.go",
            r#"
package main

import "example.com/app/request"

func GetRewriteConfig(req request.NginxRewriteReq) {
    if req.Name == "current" {
    }
}
"#,
        )
        .build();

    let line = "    if req.Name == \"current\" {";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":7,"column":{}}}]}}"#,
            column_of(line, "Name")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.com/app/request.NginxRewriteReq.Name",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "request/nginx.go",
        "{value}"
    );
}

#[test]
fn go_imported_local_receiver_field_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "store/store.go",
            r#"
package store

type Client struct {
    Name string
}
"#,
        )
        .file(
            "main.go",
            r#"
package main

import "example.com/app/store"

func Run() {
    var typed store.Client
    _ = typed.Name

    inferred := store.Client{}
    _ = inferred.Name
}
"#,
        )
        .build();

    for (line_no, line) in [(8, "    _ = typed.Name"), (11, "    _ = inferred.Name")] {
        let value = lookup(
            project.root(),
            &format!(
                r#"{{"references":[{{"path":"main.go","line":{line_no},"column":{}}}]}}"#,
                column_of(line, "Name")
            ),
        );

        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["definitions"][0]["fqn"], "example.com/app/store.Client.Name",
            "{value}"
        );
        assert_eq!(
            result["definitions"][0]["path"], "store/store.go",
            "{value}"
        );
    }
}

#[test]
fn go_unresolved_inner_local_receiver_does_not_fall_back_to_outer_binding() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

type Client struct {
    Name string
}

func Run() {
    client := Client{}
    {
        client := missing()
        _ = client.Name
    }
}
"#,
        )
        .build();

    let line = "        _ = client.Name";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":12,"column":{}}}]}}"#,
            column_of(line, "Name")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_definition", "{value}");
}

#[test]
fn go_local_pointer_struct_field_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

type PublishOptions struct {
    Fix bool
}

func NewCmdPublish() {
    opts := &PublishOptions{}
    use(&opts.Fix)
    if opts.Fix {
    }
}

func use(v *bool) {}
"#,
        )
        .build();

    let pointer_line = "    use(&opts.Fix)";
    let pointer_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":10,"column":{}}}]}}"#,
            column_of(pointer_line, "Fix")
        ),
    );
    let pointer_result = &pointer_value["results"][0];
    assert_eq!(pointer_result["status"], "resolved", "{pointer_value}");
    assert_eq!(
        pointer_result["definitions"][0]["fqn"], "example.com/app.PublishOptions.Fix",
        "{pointer_value}"
    );

    let field_line = "    if opts.Fix {";
    let field_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":11,"column":{}}}]}}"#,
            column_of(field_line, "Fix")
        ),
    );
    let field_result = &field_value["results"][0];
    assert_eq!(field_result["status"], "resolved", "{field_value}");
    assert_eq!(
        field_result["definitions"][0]["fqn"], "example.com/app.PublishOptions.Fix",
        "{field_value}"
    );
}

#[test]
fn go_receiver_struct_field_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "buf.go",
            r#"
package app

type Buf struct {
    buffer []byte
}

func (br *Buf) Reset() {
    if br.buffer == nil {
    }
}
"#,
        )
        .build();

    let line = "    if br.buffer == nil {";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"buf.go","line":9,"column":{}}}]}}"#,
            column_of(line, "br.buffer")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "app.Buf.buffer", "{value}");
}

#[test]
fn go_duplicate_promoted_fields_are_ambiguous() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

type Left struct {
    ID string
}

type Right struct {
    ID string
}

type Model struct {
    Left
    Right
}

func run(model Model) {
    _ = model.ID
}
"#,
        )
        .build();

    let line = "    _ = model.ID";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":18,"column":{}}}]}}"#,
            column_of(line, "ID")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "ambiguous", "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "ambiguous_definition",
        "{value}"
    );
}

#[test]
fn go_local_alias_to_receiver_field_resolves_field_definition() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "resolver.go",
            r#"
package resolver

type status struct {
    disabledGroups []string
}

type BlockingResolver struct {
    status *status
}

func (r *BlockingResolver) setDisabledGroups(groups []string) {
    s := r.status
    s.disabledGroups = groups
}
"#,
        )
        .build();

    let line = "    s.disabledGroups = groups";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"resolver.go","line":14,"column":{}}}]}}"#,
            column_of(line, "disabledGroups")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.com/app.status.disabledGroups",
        "{value}"
    );
}

#[test]
fn go_range_element_struct_field_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "resolver.go",
            r#"
package resolver

type scheduledGroup struct {
    group string
}

func disable(groups []scheduledGroup) {
    for _, sg := range groups {
        if sg.group == "" {
        }
    }
}
"#,
        )
        .build();

    let line = "        if sg.group == \"\" {";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"resolver.go","line":10,"column":{}}}]}}"#,
            column_of(line, "group")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.com/app.scheduledGroup.group",
        "{value}"
    );
}

#[test]
fn go_range_element_from_method_return_resolves_field_definition() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "resolver.go",
            r#"
package resolver

type scheduledGroup struct {
    group string
}

type Resolver struct{}

func (r *Resolver) collectGroups() []scheduledGroup {
    return nil
}

func (r *Resolver) disable() {
    groups := r.collectGroups()
    for _, sg := range groups {
        if sg.group == "" {
        }
    }
}
"#,
        )
        .build();

    let line = "        if sg.group == \"\" {";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"resolver.go","line":17,"column":{}}}]}}"#,
            column_of(line, "group")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.com/app.scheduledGroup.group",
        "{value}"
    );
}

#[test]
fn go_receiver_field_chain_resolves_deepest_workspace_field() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "buf.go",
            r#"
package app

import "sync"

type Buf struct {
    rw sync.RWMutex
}

func (br *Buf) Lock() {
    br.rw.Lock()
}
"#,
        )
        .build();

    let line = "    br.rw.Lock()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"buf.go","line":11,"column":{}}}]}}"#,
            column_of(line, "br.rw.Lock")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "app.Buf.rw", "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "partial_selector_chain",
        "{value}"
    );
}

#[test]
fn go_receiver_field_chain_missing_terminal_reports_partial_field() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "buf.go",
            r#"
package app

import "sync"

type Buf struct {
    rw sync.RWMutex
}

func (br *Buf) Lock() {
    br.rw.Missing()
}
"#,
        )
        .build();

    let line = "    br.rw.Missing()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"buf.go","line":11,"column":{}}}]}}"#,
            column_of(line, "br.rw.Missing")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "app.Buf.rw", "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "partial_selector_chain",
        "{value}"
    );
}

#[test]
fn go_local_binding_shadows_dot_imported_definition() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

import . "example.com/app/sub"

func Run(Helper func()) {
    Helper()
}
"#,
        )
        .file(
            "sub/sub.go",
            r#"
package sub

func Helper() {}
"#,
        )
        .build();

    let line = "    Helper()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":7,"column":{}}}]}}"#,
            column_of(line, "Helper")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert!(value["results"][0]["definitions"][0].is_null(), "{value}");
}

#[test]
fn go_unresolved_selector_does_not_fall_back_to_package_leaf() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

func Helper() {}

func Run() {
    other.Helper()
}
"#,
        )
        .build();

    let line = "    other.Helper()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":7,"column":{}}}]}}"#,
            column_of(line, "Helper")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert!(value["results"][0]["definitions"][0].is_null(), "{value}");
}

#[test]
fn java_imported_type_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("pkg/Target.java", "package pkg; public class Target {}\n")
        .file(
            "app/UseTarget.java",
            r#"
package app;

import pkg.Target;

public class UseTarget {
    private Target target;
}
"#,
        )
        .build();

    let line = "    private Target target;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseTarget.java","line":7,"column":{}}}]}}"#,
            column_of(line, "Target")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "pkg.Target", "{value}");
    assert_eq!(
        result["definitions"][0]["path"], "pkg/Target.java",
        "{value}"
    );
}

#[test]
fn java_static_import_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "pkg/Target.java",
            "package pkg; public class Target { public static void run() {} }\n",
        )
        .file(
            "app/UseTarget.java",
            r#"
package app;

import static pkg.Target.run;

public class UseTarget {
    public void call() {
        run();
    }
}
"#,
        )
        .build();

    let line = "        run();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseTarget.java","line":8,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "pkg.Target.run", "{value}");
    assert_eq!(
        result["definitions"][0]["path"], "pkg/Target.java",
        "{value}"
    );
}

#[test]
fn java_typed_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "pkg/Target.java",
            "package pkg; public class Target { public void run() {} }\n",
        )
        .file(
            "app/UseTarget.java",
            r#"
package app;

import pkg.Target;

public class UseTarget {
    public void call(Target target) {
        target.run();
    }
}
"#,
        )
        .build();

    let line = "        target.run();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseTarget.java","line":8,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "pkg.Target.run", "{value}");
    assert_eq!(
        result["definitions"][0]["path"], "pkg/Target.java",
        "{value}"
    );
}

#[test]
fn java_lombok_data_getter_resolves_to_backing_field() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/Person.java",
            r#"
package app;

import lombok.Data;

@Data
public class Person {
    private final String name;
}
"#,
        )
        .file(
            "app/UsePerson.java",
            r#"
package app;

public class UsePerson {
    String run(Person person) {
        return person.getName();
    }
}
"#,
        )
        .build();

    let line = "        return person.getName();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UsePerson.java","line":6,"column":{}}}]}}"#,
            column_of(line, "getName")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Person.name",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["kind"], "field", "{value}");
}

#[test]
fn java_lombok_data_boolean_getter_resolves_is_accessor_to_backing_field() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/Person.java",
            r#"
package app;

import lombok.Data;

@Data
public class Person {
    private final boolean ready;
}
"#,
        )
        .file(
            "app/UsePerson.java",
            r#"
package app;

public class UsePerson {
    boolean run(Person person) {
        return person.isReady();
    }
}
"#,
        )
        .build();

    let line = "        return person.isReady();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UsePerson.java","line":6,"column":{}}}]}}"#,
            column_of(line, "isReady")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Person.ready",
        "{value}"
    );
}

#[test]
fn java_lombok_data_is_getter_requires_boolean_backing_field() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/Person.java",
            r#"
package app;

import lombok.Data;

@Data
public class Person {
    private final String ready;
}
"#,
        )
        .file(
            "app/UsePerson.java",
            r#"
package app;

public class UsePerson {
    boolean run(Person person) {
        return person.isReady();
    }
}
"#,
        )
        .build();

    let line = "        return person.isReady();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UsePerson.java","line":6,"column":{}}}]}}"#,
            column_of(line, "isReady")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn java_missing_getter_without_lombok_does_not_guess_field() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/Person.java",
            r#"
package app;

public class Person {
    private final String name;
}
"#,
        )
        .file(
            "app/UsePerson.java",
            r#"
package app;

public class UsePerson {
    String run(Person person) {
        return person.getName();
    }
}
"#,
        )
        .build();

    let line = "        return person.getName();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UsePerson.java","line":6,"column":{}}}]}}"#,
            column_of(line, "getName")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn java_lombok_accessor_name_field_access_does_not_resolve_backing_field() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/Person.java",
            r#"
package app;

import lombok.Data;

@Data
public class Person {
    private final String name;
}
"#,
        )
        .file(
            "app/UsePerson.java",
            r#"
package app;

public class UsePerson {
    Object run(Person person) {
        return person.getName;
    }
}
"#,
        )
        .build();

    let line = "        return person.getName;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UsePerson.java","line":6,"column":{}}}]}}"#,
            column_of(line, "getName")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn java_lambda_parameter_field_resolves_from_collection_chain() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "Container.java",
            r#"
package app;
import java.util.ArrayList;
import java.util.NavigableMap;
import java.util.TreeMap;

class Location {
    public final String signature;
    Location(String signature) {
        this.signature = signature;
    }
}

class Container {
    public transient NavigableMap<String, ArrayList<Location>> methodMembers = new TreeMap<>();
}
"#,
        )
        .file(
            "Action.java",
            r#"
package app;

class Action {
    private final Container container = new Container();
    void run(Location method) {
        container.methodMembers.values().forEach(methods -> methods.forEach(ignored -> {
            methods.stream().filter(location -> location.signature.equals(method.signature)).forEach(location -> {});
        }));
    }
}
"#,
        )
        .build();

    let line = "            methods.stream().filter(location -> location.signature.equals(method.signature)).forEach(location -> {});";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"Action.java","line":8,"column":{}}}]}}"#,
            column_of(line, "location.signature")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Location.signature",
        "{value}"
    );
}

#[test]
fn java_method_token_on_external_field_receiver_does_not_return_field() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "Action.java",
            r#"
package app;

class Location {
    public final String signature = "";
}

class Action {
    void run(Location location) {
        location.signature.equals("");
    }
}
"#,
        )
        .build();

    let line = "        location.signature.equals(\"\");";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"Action.java","line":10,"column":{}}}]}}"#,
            column_of(line, "equals")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn java_custom_foreach_generic_does_not_infer_collection_element() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "Action.java",
            r#"
package app;

interface Consumer<T> { void accept(T value); }

class Location {
    public final String signature = "";
}

class CustomBox<T> {
    void forEach(Consumer<T> consumer) {}
}

class Action {
    void run(CustomBox<Location> box) {
        box.forEach(location -> location.signature.equals(""));
    }
}
"#,
        )
        .build();

    let line = "        box.forEach(location -> location.signature.equals(\"\"));";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"Action.java","line":16,"column":{}}}]}}"#,
            column_of(line, "location.signature")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn java_new_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "com/google/gson/GsonBuilder.java",
            "package com.google.gson; public class GsonBuilder { public GsonBuilder enableComplexMapKeySerialization() { return this; } }\n",
        )
        .file(
            "app/UseGson.java",
            r#"
package app;

import com.google.gson.GsonBuilder;

public class UseGson {
    public void call() {
        new GsonBuilder().enableComplexMapKeySerialization();
    }
}
"#,
        )
        .build();

    let line = "        new GsonBuilder().enableComplexMapKeySerialization();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseGson.java","line":8,"column":{}}}]}}"#,
            column_of(line, "enableComplexMapKeySerialization")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"],
        "com.google.gson.GsonBuilder.enableComplexMapKeySerialization",
        "{value}"
    );
}

#[test]
fn java_nested_type_constructor_resolves_from_enclosing_context() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "org/asynchttpclient/channel/ChannelPoolPartitioning.java",
            r#"
package org.asynchttpclient.channel;

public interface ChannelPoolPartitioning {
    enum PerHostChannelPoolPartitioning implements ChannelPoolPartitioning {
        INSTANCE;

        public Object getPartitionKey() {
            return new PartitionKey();
        }
    }

    class PartitionKey {
    }
}
"#,
        )
        .build();

    let line = "            return new PartitionKey();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"org/asynchttpclient/channel/ChannelPoolPartitioning.java","line":9,"column":{}}}]}}"#,
            column_of(line, "PartitionKey")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"],
        "org.asynchttpclient.channel.ChannelPoolPartitioning.PartitionKey",
        "{value}"
    );
}

#[test]
fn java_explicit_constructor_call_resolves_to_constructor_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "example/Service.java",
            r#"
package example;

public class Service {
    public Service(String name) {}
}
"#,
        )
        .file(
            "example/Consumer.java",
            r#"
package example;

public class Consumer {
    public void run() {
        new Service("job");
    }
}
"#,
        )
        .build();

    let line = "        new Service(\"job\");";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"example/Consumer.java","line":6,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.Service.Service",
        "{value}"
    );
}

#[test]
fn java_static_method_receiver_resolves_imported_type_to_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "pkg/Util.java",
            "package pkg; public class Util { public static String format(String value) { return value; } }\n",
        )
        .file(
            "app/UseUtil.java",
            r#"
package app;

import pkg.Util;

public class UseUtil {
    public String call(String value) {
        return Util.format(value);
    }
}
"#,
        )
        .build();

    let line = "        return Util.format(value);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseUtil.java","line":8,"column":{}}}]}}"#,
            column_of(line, "format")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "pkg.Util.format",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "pkg/Util.java", "{value}");
}

#[test]
fn java_method_reference_resolves_to_receiver_type_member() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/GuardianState.java",
            "package app; public class GuardianState { public boolean isFailed() { return false; } }\n",
        )
        .file(
            "app/UseGuardian.java",
            r#"
package app;

import java.util.stream.Stream;

public class UseGuardian {
    public long count(Stream<GuardianState> states) {
        return states.filter(GuardianState::isFailed).count();
    }
}
"#,
        )
        .build();

    let line = "        return states.filter(GuardianState::isFailed).count();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseGuardian.java","line":8,"column":{}}}]}}"#,
            column_of(line, "isFailed")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.GuardianState.isFailed",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "app/GuardianState.java",
        "{value}"
    );
}

#[test]
fn java_static_method_receiver_resolves_inherited_member_to_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "pkg/BaseUtil.java",
            "package pkg; public class BaseUtil { public static boolean isEmpty(String value) { return value.isEmpty(); } }\n",
        )
        .file(
            "pkg/StrUtil.java",
            "package pkg; public class StrUtil extends BaseUtil {}\n",
        )
        .file(
            "app/UseUtil.java",
            r#"
package app;

import pkg.StrUtil;

public class UseUtil {
    public boolean call(String value) {
        return StrUtil.isEmpty(value);
    }
}
"#,
        )
        .build();

    let line = "        return StrUtil.isEmpty(value);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseUtil.java","line":8,"column":{}}}]}}"#,
            column_of(line, "isEmpty")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "pkg.BaseUtil.isEmpty",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "pkg/BaseUtil.java",
        "{value}"
    );
}

#[test]
fn java_static_method_receiver_prefers_nearest_declaring_type() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "pkg/BaseUtil.java",
            "package pkg; public class BaseUtil { public static String label() { return \"base\"; } }\n",
        )
        .file(
            "pkg/StrUtil.java",
            "package pkg; public class StrUtil extends BaseUtil { public static String label() { return \"child\"; } }\n",
        )
        .file(
            "app/UseUtil.java",
            r#"
package app;

import pkg.StrUtil;

public class UseUtil {
    public String call() {
        return StrUtil.label();
    }
}
"#,
        )
        .build();

    let line = "        return StrUtil.label();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseUtil.java","line":8,"column":{}}}]}}"#,
            column_of(line, "label")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "pkg.StrUtil.label",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "pkg/StrUtil.java",
        "{value}"
    );
}

#[test]
fn java_this_field_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/Holder.java",
            r#"
package app;

public class Holder {
    private int value;

    public int read() {
        return this.value;
    }
}
"#,
        )
        .build();

    let line = "        return this.value;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Holder.java","line":8,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Holder.value",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "app/Holder.java",
        "{value}"
    );
}

#[test]
fn java_workspace_wildcard_missing_type_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("pkg/Present.java", "package pkg; public class Present {}\n")
        .file(
            "app/UseMissing.java",
            r#"
package app;

import pkg.*;

public class UseMissing {
    private MissingType value;
}
"#,
        )
        .build();

    let line = "    private MissingType value;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseMissing.java","line":7,"column":{}}}]}}"#,
            column_of(line, "MissingType")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn java_external_import_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/UseList.java",
            r#"
package app;

import java.util.List;

public class UseList {
    private List<String> values;
}
"#,
        )
        .build();

    let line = "    private List<String> values;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseList.java","line":7,"column":{}}}]}}"#,
            column_of(line, "List")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn java_local_value_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/UseLocal.java",
            r#"
package app;

public class UseLocal {
    public void run() {
        int value = 1;
        value++;
    }
}
"#,
        )
        .build();

    let line = "        value++;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseLocal.java","line":7,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn php_imported_type_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Service.php",
            "<?php\nnamespace App;\nclass Service {}\n",
        )
        .file(
            "src/Controller.php",
            "<?php\nnamespace App;\nuse App\\Service;\nclass Controller {\n    public function handle(Service $service): void {}\n}\n",
        )
        .build();

    let line = "    public function handle(Service $service): void {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Controller.php","line":5,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "App.Service", "{value}");
    assert_eq!(
        result["definitions"][0]["path"], "src/Service.php",
        "{value}"
    );
}

#[test]
fn php_instanceof_imported_type_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Mapping/Accessors/ReadonlyAccessor.php",
            "<?php\nnamespace App\\Mapping\\Accessors;\nclass ReadonlyAccessor {}\n",
        )
        .file(
            "src/UnitOfWork.php",
            "<?php\nnamespace App;\nuse App\\Mapping\\Accessors\\ReadonlyAccessor;\nclass UnitOfWork {\n    public function reset(mixed $accessor): void {\n        if (! $accessor instanceof ReadonlyAccessor) {}\n    }\n}\n",
        )
        .build();

    let line = "        if (! $accessor instanceof ReadonlyAccessor) {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/UnitOfWork.php","line":6,"column":{}}}]}}"#,
            line.find("ReadonlyAccessor").expect("ReadonlyAccessor") + 1
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.Mapping.Accessors.ReadonlyAccessor",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "src/Mapping/Accessors/ReadonlyAccessor.php",
        "{value}"
    );
}

#[test]
fn php_function_alias_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/helpers.php",
            "<?php\nnamespace App;\nfunction render_view(): void {}\n",
        )
        .file(
            "src/Controller.php",
            "<?php\nnamespace App;\nuse function App\\render_view;\nclass Controller {\n    public function handle(): void {\n        render_view();\n    }\n}\n",
        )
        .build();

    let line = "        render_view();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Controller.php","line":6,"column":{}}}]}}"#,
            column_of(line, "render_view")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.render_view",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "src/helpers.php",
        "{value}"
    );
}

#[test]
fn php_typed_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Service.php",
            "<?php\nnamespace App;\nclass Service {\n    public function run(): void {}\n}\n",
        )
        .file(
            "src/Controller.php",
            "<?php\nnamespace App;\nclass Controller {\n    public function handle(Service $service): void {\n        $service->run();\n    }\n}\n",
        )
        .build();

    let line = "        $service->run();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Controller.php","line":5,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.Service.run",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "src/Service.php",
        "{value}"
    );
}

#[test]
fn php_fully_qualified_type_resolves_from_final_segment() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Service.php",
            "<?php\nnamespace App;\nclass Service {}\n",
        )
        .file(
            "src/Controller.php",
            "<?php\nnamespace App;\nclass Controller {\n    public function handle(\\App\\Service $service): void {}\n}\n",
        )
        .build();

    let line = "    public function handle(\\App\\Service $service): void {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Controller.php","line":4,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "App.Service", "{value}");
}

#[test]
fn php_parent_static_call_resolves_to_parent_definition() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/BaseController.php",
            "<?php\nnamespace App;\nclass BaseController {\n    public function run(): void {}\n}\n",
        )
        .file(
            "src/ChildController.php",
            "<?php\nnamespace App;\nclass ChildController extends BaseController {\n    public function run(): void {}\n    public function call(): void {\n        parent::run();\n    }\n}\n",
        )
        .build();

    let line = "        parent::run();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/ChildController.php","line":6,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.BaseController.run",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "src/BaseController.php",
        "{value}"
    );
}

#[test]
fn php_parent_constructor_resolves_to_nearest_inherited_definition() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/GrandBase.php",
            "<?php\nnamespace App;\nclass GrandBase {\n    public function __construct() {}\n}\n",
        )
        .file(
            "src/BaseController.php",
            "<?php\nnamespace App;\nclass BaseController extends GrandBase {}\n",
        )
        .file(
            "src/ChildController.php",
            "<?php\nnamespace App;\nclass ChildController extends BaseController {\n    public function call(): void {\n        parent::__construct();\n    }\n}\n",
        )
        .build();

    let line = "        parent::__construct();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/ChildController.php","line":5,"column":{}}}]}}"#,
            column_of(line, "__construct")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.GrandBase.__construct",
        "{value}"
    );
}

#[test]
fn php_inherited_member_resolves_parent_with_multiline_extends() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/BaseController.php",
            "<?php\nnamespace App;\nclass BaseController {\n    public function run(): void {}\n}\n",
        )
        .file(
            "src/ChildController.php",
            "<?php\nnamespace App;\nclass ChildController extends\n    BaseController {\n    public function call(): void {\n        parent::run();\n    }\n}\n",
        )
        .build();

    let line = "        parent::run();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/ChildController.php","line":6,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.BaseController.run",
        "{value}"
    );
}

#[test]
fn php_self_class_constant_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/SchemaTool.php",
            "<?php\nnamespace App;\nclass SchemaTool {\n    private const KNOWN_COLUMN_OPTIONS = [];\n    public function gather(): void {\n        $options = self::KNOWN_COLUMN_OPTIONS;\n    }\n}\n",
        )
        .build();

    let line = "        $options = self::KNOWN_COLUMN_OPTIONS;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/SchemaTool.php","line":6,"column":{}}}]}}"#,
            column_of(line, "KNOWN_COLUMN_OPTIONS")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.SchemaTool.KNOWN_COLUMN_OPTIONS",
        "{value}"
    );
}

#[test]
fn php_enum_cases_resolve_as_static_members() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "app/Permissions/Permission.php",
            r#"
<?php

namespace App\Permissions;

enum Permission: string
{
    case PageUpdate = 'page-update';
    case PageView = 'page-view';
}
"#,
        )
        .file(
            "app/Uploads/AttachmentController.php",
            r#"
<?php

namespace App\Uploads;

use App\Permissions\Permission;

class AttachmentController
{
    public function update(): void
    {
        $this->check(Permission::PageView);
    }
}
"#,
        )
        .build();

    let line = "        $this->check(Permission::PageView);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Uploads/AttachmentController.php","line":12,"column":{}}}]}}"#,
            column_of(line, "PageView")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.Permissions.Permission.PageView",
        "{value}"
    );
}

#[test]
fn php_promoted_constructor_properties_resolve_as_instance_members() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "app/Queries/PageQueries.php",
            r#"
<?php

namespace App\Queries;

class PageQueries
{
}
"#,
        )
        .file(
            "app/Uploads/AttachmentController.php",
            r#"
<?php

namespace App\Uploads;

use App\Queries\PageQueries;

class AttachmentController
{
    public function __construct(
        protected PageQueries $pageQueries,
    ) {
    }

    public function attachLink(): void
    {
        $page = $this->pageQueries;
    }
}
"#,
        )
        .build();

    let line = "        $page = $this->pageQueries;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Uploads/AttachmentController.php","line":17,"column":{}}}]}}"#,
            column_of(line, "pageQueries")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.Uploads.AttachmentController.pageQueries",
        "{value}"
    );
}

#[test]
fn php_prefix_only_external_import_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Controller/Controller.php",
            "<?php\nnamespace Vendor\\Package\\Controller;\nclass Controller {}\n",
        )
        .file(
            "src/App.php",
            "<?php\nnamespace App;\nuse Vendor\\Package\\Service;\nclass App {\n    public function handle(Service $service): void {}\n}\n",
        )
        .build();

    let line = "    public function handle(Service $service): void {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/App.php","line":5,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn php_external_type_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Controller.php",
            "<?php\nnamespace App;\nuse Vendor\\Package\\Service;\nclass Controller {\n    public function handle(Service $service): void {}\n}\n",
        )
        .build();

    let line = "    public function handle(Service $service): void {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Controller.php","line":5,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn php_local_value_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Controller.php",
            "<?php\nnamespace App;\nclass Controller {\n    public function handle(): void {\n        $value = 1;\n        $value++;\n    }\n}\n",
        )
        .build();

    let line = "        $value++;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Controller.php","line":5,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn python_from_import_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("pkg/util.py", "def helper():\n    pass\n")
        .file(
            "app.py",
            "from pkg.util import helper\n\ndef run():\n    helper()\n",
        )
        .build();

    let line = "    helper()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.py","line":4,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "pkg.util.helper",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "pkg/util.py", "{value}");
}

#[test]
fn python_namespace_import_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("pkg/util.py", "def helper():\n    pass\n")
        .file(
            "app.py",
            "import pkg.util as util\n\ndef run():\n    util.helper()\n",
        )
        .build();

    let line = "    util.helper()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.py","line":4,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "pkg.util.helper",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "pkg/util.py", "{value}");
}

#[test]
fn python_attribute_object_resolves_to_namespace_not_member() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("pkg/util.py", "def helper():\n    pass\n")
        .file(
            "app.py",
            "import pkg.util as util\n\ndef run():\n    util.helper()\n",
        )
        .build();

    let line = "    util.helper()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.py","line":4,"column":{}}}]}}"#,
            column_of(line, "util")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "pkg.util", "{value}");
    assert_eq!(result["definitions"][0]["path"], "pkg/util.py", "{value}");
}

#[test]
fn python_plain_dotted_import_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("pkg/util.py", "def helper():\n    pass\n")
        .file(
            "app.py",
            "import pkg.util\n\ndef run():\n    pkg.util.helper()\n",
        )
        .build();

    let line = "    pkg.util.helper()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.py","line":4,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "pkg.util.helper",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "pkg/util.py", "{value}");
}

#[test]
fn python_typed_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            "class Service:\n    def run(self):\n        pass\n",
        )
        .file(
            "app.py",
            "from service import Service\n\ndef handle(service: Service):\n    service.run()\n",
        )
        .build();

    let line = "    service.run()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.py","line":4,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "service.Service.run",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "service.py", "{value}");
}

#[test]
fn python_typed_receiver_inherited_method_resolves_to_base_definition() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            "class Base:\n    def run(self):\n        pass\n\nclass Child(Base):\n    pass\n",
        )
        .file(
            "app.py",
            "from service import Child\n\ndef handle(service: Child):\n    service.run()\n",
        )
        .build();

    let line = "    service.run()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.py","line":4,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "service.Base.run",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "service.py", "{value}");
}

#[test]
fn python_unimported_receiver_annotation_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "other.py",
            "class Service:\n    def run(self):\n        pass\n",
        )
        .file(
            "app.py",
            "def handle(service: Service):\n    service.run()\n",
        )
        .build();

    let line = "    service.run()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.py","line":2,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn python_external_import_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "app.py",
            "import requests\n\ndef run():\n    requests.get()\n",
        )
        .build();

    let line = "    requests.get()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.py","line":4,"column":{}}}]}}"#,
            column_of(line, "get")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn python_local_value_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", "def run():\n    value = 1\n    value\n")
        .build();

    let line = "    value";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.py","line":3,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn csharp_using_type_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib/Service.cs",
            "namespace Lib { public class Service {} }\n",
        )
        .file(
            "App/Controller.cs",
            "using Lib;\nnamespace App { public class Controller { private Service service; } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { private Service service; } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Lib.Service", "{value}");
    assert_eq!(
        result["definitions"][0]["path"], "Lib/Service.cs",
        "{value}"
    );
}

#[test]
fn csharp_typed_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib/Service.cs",
            "namespace Lib { public class Service { public void Run() {} } }\n",
        )
        .file(
            "App/Controller.cs",
            "using Lib;\nnamespace App { public class Controller { public void Handle(Service service) { service.Run(); } } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { public void Handle(Service service) { service.Run(); } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "Run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Lib.Service.Run",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "Lib/Service.cs",
        "{value}"
    );
}

#[test]
fn csharp_visible_enum_member_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib/Modes.cs",
            "namespace Lib { public enum Mode { Read, Write } }\n",
        )
        .file(
            "App/Controller.cs",
            "using Lib;\nnamespace App { public class Controller { public void Handle() { var mode = Mode.Read; } } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { public void Handle() { var mode = Mode.Read; } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "Read")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Lib.Mode.Read", "{value}");
    assert_eq!(result["definitions"][0]["path"], "Lib/Modes.cs", "{value}");
}

#[test]
fn csharp_visible_enum_receiver_type_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib/Modes.cs",
            "namespace Lib { public enum Mode { Read, Write } }\n",
        )
        .file(
            "App/Controller.cs",
            "using Lib;\nnamespace App { public class Controller { public void Handle() { var mode = Mode.Read; } } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { public void Handle() { var mode = Mode.Read; } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "Mode")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Lib.Mode", "{value}");
    assert_eq!(result["definitions"][0]["path"], "Lib/Modes.cs", "{value}");
}

#[test]
fn csharp_enum_declaration_name_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib/Modes.cs",
            "namespace Lib { public enum Mode { Read, Write } }\n",
        )
        .build();

    let line = "namespace Lib { public enum Mode { Read, Write } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"Lib/Modes.cs","line":1,"column":{}}},{{"path":"Lib/Modes.cs","line":1,"column":{}}}]}}"#,
            column_of(line, "Mode"),
            column_of(line, "Read")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert_eq!(value["results"][1]["status"], "no_definition", "{value}");
}

#[test]
fn csharp_same_namespace_static_property_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App/App.cs",
            "namespace App { public partial class App { public static ResourceDictionary ResourceDictionary { get; private set; } } public class ResourceDictionary {} }\n",
        )
        .file(
            "App/Bootstrapper.cs",
            "namespace App { public class Bootstrapper { public void Start() { var value = App.ResourceDictionary; } } }\n",
        )
        .build();

    let line = "namespace App { public class Bootstrapper { public void Start() { var value = App.ResourceDictionary; } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Bootstrapper.cs","line":1,"column":{}}}]}}"#,
            column_of(line, "ResourceDictionary")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.App.ResourceDictionary",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "App/App.cs", "{value}");
}

#[test]
fn csharp_same_namespace_static_receiver_type_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App/App.cs",
            "namespace App { public partial class App { public static ResourceDictionary ResourceDictionary { get; private set; } } public class ResourceDictionary {} }\n",
        )
        .file(
            "App/Bootstrapper.cs",
            "namespace App { public class Bootstrapper { public void Start() { var value = App.ResourceDictionary; } } }\n",
        )
        .build();

    let line = "namespace App { public class Bootstrapper { public void Start() { var value = App.ResourceDictionary; } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Bootstrapper.cs","line":1,"column":{}}}]}}"#,
            column_of(line, "App.ResourceDictionary")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "App.App", "{value}");
    assert_eq!(result["definitions"][0]["path"], "App/App.cs", "{value}");
}

#[test]
fn csharp_instance_member_receiver_resolves_from_enclosing_property_type() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App/List.cs",
            "namespace App { public class List<T> { public class Node<T> { public T Data { get; set; } } private Node<T> lastNode { get; set; } public T Last() { return lastNode.Data; } } }\n",
        )
        .build();

    let line = "namespace App { public class List<T> { public class Node<T> { public T Data { get; set; } } private Node<T> lastNode { get; set; } public T Last() { return lastNode.Data; } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/List.cs","line":1,"column":{}}}]}}"#,
            column_of(line, "Data;")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.List$Node.Data",
        "{value}"
    );
}

#[test]
fn csharp_var_initialized_from_instance_member_seeds_receiver_type() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App/List.cs",
            "namespace App { public class List<T> { public class Node<T> { public Node<T> Next { get; set; } public T Data { get; set; } } private Node<T> firstNode { get; set; } public T Get() { var currentNode = firstNode; currentNode = currentNode.Next; return currentNode.Data; } } }\n",
        )
        .build();

    let line = "namespace App { public class List<T> { public class Node<T> { public Node<T> Next { get; set; } public T Data { get; set; } } private Node<T> firstNode { get; set; } public T Get() { var currentNode = firstNode; currentNode = currentNode.Next; return currentNode.Data; } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/List.cs","line":1,"column":{}}},{{"path":"App/List.cs","line":1,"column":{}}}]}}"#,
            column_of(line, "Next;"),
            column_of(line, "Data;")
        ),
    );

    for result in value["results"].as_array().unwrap() {
        assert_eq!(result["status"], "resolved", "{value}");
    }
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "App.List$Node.Next",
        "{value}"
    );
    assert_eq!(
        value["results"][1]["definitions"][0]["fqn"], "App.List$Node.Data",
        "{value}"
    );
}

#[test]
fn csharp_extension_method_resolves_from_visible_namespace() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Dapper/SqlMapper.cs",
            "namespace Dapper { public static class SqlMapper { public static T QueryFirst<T>(this IDbConnection cnn, string sql, object? param = null) => default!; public static dynamic QueryFirst(this IDbConnection cnn, string sql) => default!; } }\n",
        )
        .file(
            "App/Repo.cs",
            "using Dapper;\nusing System.Data;\nnamespace App { class Repo { public int Load(IDbConnection connection) { return connection.QueryFirst<int>(\"select 1\"); } } }\n",
        )
        .build();

    let line = "namespace App { class Repo { public int Load(IDbConnection connection) { return connection.QueryFirst<int>(\"select 1\"); } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Repo.cs","line":3,"column":{}}}]}}"#,
            column_of(line, "QueryFirst")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Dapper.SqlMapper.QueryFirst",
        "{value}"
    );
}

#[test]
fn csharp_typed_receiver_method_filters_overloads_by_call_arity() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib/Service.cs",
            "namespace Lib { public class Service { public void GetFilePaths(string path) {} public void GetFilePaths(string path, bool clearCache) {} } }\n",
        )
        .file(
            "App/Controller.cs",
            "using Lib;\nnamespace App { public class Controller { public void Handle(Service service, string folder, bool clearCache) { service.GetFilePaths(folder, clearCache); } } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { public void Handle(Service service, string folder, bool clearCache) { service.GetFilePaths(folder, clearCache); } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "GetFilePaths")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Lib.Service.GetFilePaths",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["signature"], "(string, bool)",
        "{value}"
    );
}

#[test]
fn csharp_explicit_constructor_call_resolves_to_constructor_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib/Service.cs",
            "namespace Lib { public class Service { public Service(string name) {} } }\n",
        )
        .file(
            "App/Controller.cs",
            "using Lib;\nnamespace App { public class Controller { public void Handle() { var service = new Service(\"job\"); } } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { public void Handle() { var service = new Service(\"job\"); } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Lib.Service.Service",
        "{value}"
    );
}

#[test]
fn csharp_typed_receiver_method_wrong_arity_returns_overload_definitions() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib/Service.cs",
            "namespace Lib { public class Service { public void GetFilePaths(string path) {} public void GetFilePaths(string path, bool clearCache) {} } }\n",
        )
        .file(
            "App/Controller.cs",
            "using Lib;\nnamespace App { public class Controller { public void Handle(Service service, string folder, bool clearCache, int depth) { service.GetFilePaths(folder, clearCache, depth); } } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { public void Handle(Service service, string folder, bool clearCache, int depth) { service.GetFilePaths(folder, clearCache, depth); } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "GetFilePaths")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        2,
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["fqn"], "Lib.Service.GetFilePaths",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["signature"], "(string)", "{value}");
    assert_eq!(
        result["definitions"][1]["signature"], "(string, bool)",
        "{value}"
    );
}

#[test]
fn csharp_inherited_member_prefers_nearest_declaring_type() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib/Types.cs",
            "namespace Lib { public class Grand { public void Run() {} } public class Base : Grand { public new void Run() {} } public class Child : Base {} }\n",
        )
        .file(
            "App/Controller.cs",
            "using Lib;\nnamespace App { public class Controller { public void Handle(Child child) { child.Run(); } } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { public void Handle(Child child) { child.Run(); } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "Run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Lib.Base.Run", "{value}");
}

#[test]
fn csharp_this_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App/Controller.cs",
            "namespace App { public class Controller { public void Run() {} public void Handle() { this.Run(); } } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { public void Run() {} public void Handle() { this.Run(); } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":1,"column":{}}}]}}"#,
            column_of(line, "Run();")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.Controller.Run",
        "{value}"
    );
}

#[test]
fn csharp_external_using_reports_boundary() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App/Controller.cs",
            "using External;\nnamespace App { public class Controller { private Service service; } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { private Service service; } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn csharp_local_value_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App.cs",
            "class App { void Run() { var value = 1; value++; } }\n",
        )
        .build();

    let line = "class App { void Run() { var value = 1; value++; } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App.cs","line":1,"column":{}}}]}}"#,
            column_of(line, "value++")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn csharp_delegate_parameter_shadow_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App.cs",
            "using System;\nclass App { void Run() {} void Handle(Action Run) { Run(); } }\n",
        )
        .build();

    let line = "class App { void Run() {} void Handle(Action Run) { Run(); } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "Run();")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn csharp_local_function_shadow_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App.cs",
            "class App { void Run() {} void Handle() { void Run() {} Run(); } }\n",
        )
        .build();

    let line = "class App { void Run() {} void Handle() { void Run() {} Run(); } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App.cs","line":1,"column":{}}}]}}"#,
            column_of(line, "Run();")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn csharp_ambiguous_using_type_returns_ambiguous() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("A/Service.cs", "namespace A { public class Service {} }\n")
        .file("B/Service.cs", "namespace B { public class Service {} }\n")
        .file(
            "App.cs",
            "using A;\nusing B;\nclass App { private Service service; }\n",
        )
        .build();

    let line = "class App { private Service service; }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App.cs","line":3,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    assert_eq!(value["results"][0]["status"], "ambiguous", "{value}");
    assert!(value["results"][0]["definitions"][0].is_null(), "{value}");
}

#[test]
fn csharp_alias_external_using_reports_boundary() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App.cs",
            "using Svc = External.Service;\nclass App { private Svc service; }\n",
        )
        .build();

    let line = "class App { private Svc service; }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "Svc")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn csharp_static_external_using_reports_boundary() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App.cs",
            "using static External.Helpers;\nclass App { void Handle() { Help(); } }\n",
        )
        .build();

    let line = "class App { void Handle() { Help(); } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "Help")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn cpp_included_type_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("target.h", "namespace ns { class Service {}; }\n")
        .file("app.cpp", "#include \"target.h\"\nns::Service service;\n")
        .build();

    let line = "ns::Service service;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "ns.Service", "{value}");
    assert_eq!(result["definitions"][0]["path"], "target.h", "{value}");
}

#[test]
fn cpp_constructor_call_resolves_to_header_constructor_declaration() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "service.h",
            "namespace example { class Repository {}; class Service { public: explicit Service(Repository& repository); }; }\n",
        )
        .file(
            "service.cpp",
            "#include \"service.h\"\nnamespace example { Service::Service(Repository& repository) {} Service build_service(Repository& repository) { return Service(repository); } }\n",
        )
        .build();

    let line = "namespace example { Service::Service(Repository& repository) {} Service build_service(Repository& repository) { return Service(repository); } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"service.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "Service(repository)")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.Service.Service",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "service.h", "{value}");
}

#[test]
fn cpp_braced_constructor_call_resolves_to_matching_constructor_declaration() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.h",
            "namespace ns { class Target { public: Target(); explicit Target(int value); }; }\n",
        )
        .file(
            "app.cpp",
            "#include \"target.h\"\nnamespace ns { Target make() { return Target{1}; } }\n",
        )
        .build();

    let line = "namespace ns { Target make() { return Target{1}; } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "Target{1}")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "ns.Target.Target",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["signature"], "(int)", "{value}");
    assert_eq!(result["definitions"][0]["path"], "target.h", "{value}");
}

#[test]
fn cpp_typed_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.h",
            "namespace ns { class Service { public: void run(); }; }\n",
        )
        .file(
            "target.cpp",
            "#include \"target.h\"\nnamespace ns { void Service::run() {} }\n",
        )
        .file(
            "app.cpp",
            "#include \"target.h\"\nvoid handle(ns::Service service) { service.run(); }\n",
        )
        .build();

    let line = "void handle(ns::Service service) { service.run(); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "ns.Service.run", "{value}");
}

#[test]
fn cpp_typed_receiver_method_filters_overloads_by_call_arity() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.h",
            "namespace ns { class DataReader {}; class Net { public: int load_model(); int load_model(const DataReader& dr); }; }\n",
        )
        .file(
            "app.cpp",
            "#include \"target.h\"\nvoid handle(ns::Net& net, const ns::DataReader& dr) { net.load_model(dr); }\n",
        )
        .build();

    let line = "void handle(ns::Net& net, const ns::DataReader& dr) { net.load_model(dr); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "load_model")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "ns.Net.load_model",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["signature"], "(DataReader &)",
        "{value}"
    );
}

#[test]
fn cpp_typed_receiver_method_wrong_arity_returns_overload_definitions() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.h",
            "namespace ns { class DataReader {}; class Net { public: int load_model(); int load_model(const DataReader& dr); }; }\n",
        )
        .file(
            "app.cpp",
            "#include \"target.h\"\nvoid handle(ns::Net& net, const ns::DataReader& dr) { net.load_model(dr, dr); }\n",
        )
        .build();

    let line = "void handle(ns::Net& net, const ns::DataReader& dr) { net.load_model(dr, dr); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "load_model")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        2,
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["fqn"], "ns.Net.load_model",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["signature"], "()", "{value}");
    assert_eq!(
        result["definitions"][1]["signature"], "(DataReader &)",
        "{value}"
    );
}

#[test]
fn cpp_typed_receiver_method_filters_overloads_by_argument_type() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.h",
            "namespace ns { class DataReader {}; class DataReaderFromMemory : public DataReader {}; class Net { public: int load_model(const char* path); int load_model(const DataReader& dr); }; }\n",
        )
        .file(
            "app.cpp",
            "#include \"target.h\"\nusing namespace ns;\nclass DataReaderFromMemoryCopy : public DataReaderFromMemory {};\nvoid bind(Net& net, DataReaderFromMemoryCopy& dr) { net.load_model(dr); }\n",
        )
        .build();

    let line = "void bind(Net& net, DataReaderFromMemoryCopy& dr) { net.load_model(dr); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":4,"column":{}}}]}}"#,
            column_of(line, "load_model")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "ns.Net.load_model",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["signature"], "(DataReader &)",
        "{value}"
    );
}

#[test]
fn cpp_typed_receiver_method_wrong_argument_type_returns_overload_definitions() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.h",
            "namespace ns { class DataReader {}; class Other {}; class Net { public: int load_model(const char* path); int load_model(const DataReader& dr); }; }\n",
        )
        .file(
            "app.cpp",
            "#include \"target.h\"\nusing namespace ns;\nvoid bind(Net& net, Other& other) { net.load_model(other); }\n",
        )
        .build();

    let line = "void bind(Net& net, Other& other) { net.load_model(other); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":3,"column":{}}}]}}"#,
            column_of(line, "load_model")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        2,
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["fqn"], "ns.Net.load_model",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["signature"], "(DataReader &)",
        "{value}"
    );
    assert_eq!(result["definitions"][1]["signature"], "(char *)", "{value}");
}

#[test]
fn cpp_typed_receiver_method_filters_pointer_overload_by_argument_indirection() {
    // A pointer argument must select the `Widget*` overload over the `Widget`
    // value overload. This is the case the old workspace-pointer escape hatch
    // bailed on (returning both); indirection-aware matching resolves it.
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.h",
            "namespace ns { class Widget {}; class Sink { public: int accept(Widget w); int accept(Widget* w); }; }\n",
        )
        .file(
            "app.cpp",
            "#include \"target.h\"\nusing namespace ns;\nvoid bind(Sink& sink, Widget* wp) { sink.accept(wp); }\n",
        )
        .build();

    let line = "void bind(Sink& sink, Widget* wp) { sink.accept(wp); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":3,"column":{}}}]}}"#,
            column_of(line, "accept")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "{value}"
    );
    assert_eq!(result["definitions"][0]["fqn"], "ns.Sink.accept", "{value}");
    assert_eq!(
        result["definitions"][0]["signature"], "(Widget *)",
        "{value}"
    );
}

#[test]
fn cpp_typed_receiver_method_filters_value_overload_by_argument_indirection() {
    // The mirror of the pointer case: a value argument must select the `Widget`
    // overload over the `Widget*` overload.
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.h",
            "namespace ns { class Widget {}; class Sink { public: int accept(Widget w); int accept(Widget* w); }; }\n",
        )
        .file(
            "app.cpp",
            "#include \"target.h\"\nusing namespace ns;\nvoid bind(Sink& sink, Widget w) { sink.accept(w); }\n",
        )
        .build();

    let line = "void bind(Sink& sink, Widget w) { sink.accept(w); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":3,"column":{}}}]}}"#,
            column_of(line, "accept")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "{value}"
    );
    assert_eq!(result["definitions"][0]["fqn"], "ns.Sink.accept", "{value}");
    assert_eq!(result["definitions"][0]["signature"], "(Widget)", "{value}");
}

#[test]
fn cpp_chained_struct_field_receiver_resolves_member_field() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("bstr.h", "struct bstr { int len; };\n")
        .file(
            "app.c",
            "#include \"bstr.h\"\nstruct tmp_buffers { struct bstr write_console_buf; };\nint read_len(struct tmp_buffers *buffers) { return buffers->write_console_buf.len; }\n",
        )
        .build();

    let line =
        "int read_len(struct tmp_buffers *buffers) { return buffers->write_console_buf.len; }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.c","line":3,"column":{}}}]}}"#,
            line.rfind("len").expect("field in line") + 1
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "bstr.len", "{value}");
}

#[test]
fn cpp_typedef_struct_value_parameter_resolves_member_field() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "include/lib/raw.h",
            r#"
#ifndef LIB_RAW_H
#define LIB_RAW_H
#ifdef __cplusplus
extern "C" {
#endif
typedef struct RawData { unsigned char * data; unsigned long size; } RawData;
#ifdef __cplusplus
}
#endif
#endif
"#,
        )
        .file(
            "apps/shared/raw_reader.h",
            "#include \"lib/raw.h\"\nint read_len(const RawData raw);\n",
        )
        .file(
            "apps/shared/app.c",
            "#include \"raw_reader.h\"\nint read_len(const RawData raw) { return raw.size; }\n",
        )
        .build();

    let line = "int read_len(const RawData raw) { return raw.size; }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"apps/shared/app.c","line":2,"column":{}}}]}}"#,
            column_of(line, "size")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "RawData.size", "{value}");
}

#[test]
fn cpp_local_type_uses_class_body_over_forward_declaration() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
class DeepImage;
class Image {
public:
    void resize();
};
class DeepImage : public Image {
public:
    void level();
};
void run() {
    DeepImage img;
    img.resize();
    img.level();
}
"#,
        )
        .build();

    let resize = "    img.resize();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":13,"column":{}}},{{"path":"app.cpp","line":14,"column":{}}}]}}"#,
            column_of(resize, "resize"),
            column_of("    img.level();", "level")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "Image.resize",
        "{value}"
    );
    assert_eq!(value["results"][1]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][1]["definitions"][0]["fqn"], "DeepImage.level",
        "{value}"
    );
}

#[test]
fn cpp_elaborated_return_type_function_is_not_recovered_as_class() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
class RawData {};
class RawData make() {
    return RawData{};
}
void consume(make *ptr) {}
"#,
        )
        .build();

    let line = "void consume(make *ptr) {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":6,"column":{}}}]}}"#,
            column_of(line, "make")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_definition", "{value}");
}

#[test]
fn cpp_multi_declarator_local_declaration_reuses_shared_type() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
struct RawData {
    void use();
};
void run() {
    RawData first, second;
    second.use();
}
"#,
        )
        .build();

    let line = "    second.use();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":7,"column":{}}}]}}"#,
            column_of(line, "use")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "RawData.use", "{value}");
}

#[test]
fn cpp_export_macro_class_body_seeds_local_receiver_type() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
#define API
#define NS_ENTER namespace Project {
#define NS_EXIT }
NS_ENTER
class Image {
public:
    void resize();
};
class API DeepImage : public Image {
public:
    void level();
};
NS_EXIT
void run() {
    DeepImage img;
    img.resize();
    img.level();
}
"#,
        )
        .build();

    let value = lookup(
        project.root(),
        r#"{"references":[{"path":"app.cpp","line":17,"column":9},{"path":"app.cpp","line":18,"column":9}]}"#,
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "Image.resize",
        "{value}"
    );
    assert_eq!(value["results"][1]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][1]["definitions"][0]["fqn"], "DeepImage.level",
        "{value}"
    );
}

#[test]
fn cpp_macro_decorated_local_type_seeds_receiver_binding() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
#define API

struct RawData {
    void use();
};

void run() {
    API RawData raw;
    raw.use();
}
"#,
        )
        .build();

    let line = "    raw.use();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":10,"column":{}}}]}}"#,
            column_of(line, "use")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "RawData.use",
        "{value}"
    );
}

#[test]
fn cpp_function_like_macro_decorated_local_type_seeds_receiver_binding() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
#define API_ATTR(x)

struct RawData {
    void use();
};

void run() {
    API_ATTR(foo) RawData raw;
    raw.use();
}
"#,
        )
        .build();

    let line = "    raw.use();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":10,"column":{}}}]}}"#,
            column_of(line, "use")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "RawData.use",
        "{value}"
    );
}

#[test]
fn cpp_macro_decorated_multi_declarator_reuses_shared_type() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
#define API

struct RawData {
    void use();
};

void run() {
    API RawData first, second;
    second.use();
}
"#,
        )
        .build();

    let line = "    second.use();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":10,"column":{}}}]}}"#,
            column_of(line, "use")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "RawData.use",
        "{value}"
    );
}

#[test]
fn cpp_macro_decorated_multi_declarator_keeps_pointer_depth_per_declarator() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
#define API

struct RawData {
    void use();
};

void run() {
    API RawData *first, second;
    second.use();
}
"#,
        )
        .build();

    let line = "    second.use();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":10,"column":{}}}]}}"#,
            column_of(line, "use")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "RawData.use",
        "{value}"
    );
}

#[test]
fn cpp_macro_decorated_multi_declarator_preserves_pointer_depth_on_later_pointer() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
#define API

struct RawData {
    void use();
};

void run() {
    API RawData first, *second;
    second->use();
}
"#,
        )
        .build();

    let line = "    second->use();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":10,"column":{}}}]}}"#,
            column_of(line, "use")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "RawData.use",
        "{value}"
    );
}

#[test]
fn cpp_local_function_declaration_does_not_seed_receiver_binding() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            "class Widget { public: void run(); };\nWidget make(int);\nvoid handle() { make.run(); }\n",
        )
        .build();

    let line = "void handle() { make.run(); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":3,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_local_function_declaration_with_builtin_pointer_does_not_seed_receiver_binding() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            "class Widget { public: void run(); };\nWidget make(const unsigned char* mem);\nvoid handle() { make.run(); }\n",
        )
        .build();

    let line = "void handle() { make.run(); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":3,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_workspace_angle_include_receiver_method_resolves_to_definition() {
    let header = "#define API\nnamespace ns { class API Service { public: void run(); }; }\n";
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("include/target.h", header)
        .file(
            "target.cpp",
            "#include \"include/target.h\"\nnamespace ns { void Service::run() {} }\n",
        )
        .file(
            "src/app.cpp",
            "#include <target.h>\nusing namespace ns;\nvoid handle(Service& service) { service.run(); }\n",
        )
        .build();

    let line = "void handle(Service& service) { service.run(); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/app.cpp","line":3,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "ns.Service.run", "{value}");
}

#[test]
fn cpp_workspace_angle_include_missing_type_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("target.h", "namespace ns { class Service {}; }\n")
        .file(
            "src/app.cpp",
            "#include <target.h>\nusing namespace ns;\nMissingType value;\n",
        )
        .build();

    let line = "MissingType value;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/app.cpp","line":3,"column":{}}}]}}"#,
            column_of(line, "MissingType")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_export_macro_class_recovery_handles_header_variants() {
    let cases = [
        (
            "final class",
            "#define API\nnamespace ns { class API Service final { public: void run(); }; }\n",
            "ns.Service.run",
        ),
        (
            "single macro with base",
            "#define API_EXPORT\nnamespace ns { class Base {}; class API_EXPORT Service : public Base { public: void run(); }; }\n",
            "ns.Service.run",
        ),
        (
            "multiple macros",
            "#define DLL_PUBLIC\n#define API\nnamespace ns { class DLL_PUBLIC API Service { public: void run(); }; }\n",
            "ns.Service.run",
        ),
        (
            "struct macro",
            "#define API\nnamespace ns { struct API Service { void run(); }; }\n",
            "ns.Service.run",
        ),
        (
            "function-like namespace macro",
            "#define NS_ENTER(name) namespace name {\n#define NS_EXIT }\n#define API\nNS_ENTER(ns)\nclass API Service { public: void run(); };\nNS_EXIT\n",
            "Service.run",
        ),
    ];

    for (name, header, expected_fqn) in cases {
        let project = InlineTestProject::with_language(Language::Cpp)
            .file("include/target.h", header)
            .file(
                "target.cpp",
                "#include \"include/target.h\"\nnamespace ns { void Service::run() {} }\n",
            )
            .file(
                "src/app.cpp",
                "#include <target.h>\nusing namespace ns;\nvoid handle(Service& service) { service.run(); }\n",
            )
            .build();

        let line = "void handle(Service& service) { service.run(); }";
        let value = lookup(
            project.root(),
            &format!(
                r#"{{"references":[{{"path":"src/app.cpp","line":3,"column":{}}}]}}"#,
                column_of(line, "run")
            ),
        );

        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{name}: {value}");
        assert_eq!(
            result["definitions"][0]["fqn"], expected_fqn,
            "{name}: {value}"
        );
    }
}

#[test]
fn cpp_relative_namespace_call_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            "namespace ns { namespace detail { void helper() {} } void run() { detail::helper(); } }\n",
        )
        .build();

    let line =
        "namespace ns { namespace detail { void helper() {} } void run() { detail::helper(); } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":1,"column":{}}}]}}"#,
            column_of(line, "helper();")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "ns::detail.helper",
        "{value}"
    );
}

#[test]
fn cpp_range_for_pointer_binding_resolves_member_field() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "graph.h",
            r#"
namespace ns {
class Operator { public: int params; };
class Graph { public: Operator* ops; };
}
"#,
        )
        .file(
            "app.cpp",
            r#"
#include "graph.h"
using namespace ns;
void run(Graph& graph) {
    for (Operator* op : graph.ops) {
        op->params = 1;
    }
}
"#,
        )
        .build();

    let line = "        op->params = 1;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":6,"column":{}}}]}}"#,
            column_of(line, "params")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "ns.Operator.params",
        "{value}"
    );
}

#[test]
fn cpp_external_include_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            "#include <external/service.h>\nService service;\n",
        )
        .build();

    let line = "Service service;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn cpp_extensionless_angle_include_with_unrelated_basename_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("vendor/vector", "namespace local { class NotStd {}; }\n")
        .file("app.cpp", "#include <vector>\nstd::Vector values;\n")
        .build();

    let line = "std::Vector values;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "Vector")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn cpp_local_value_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("app.cpp", "void run() { int value = 1; value++; }\n")
        .build();

    let line = "void run() { int value = 1; value++; }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":1,"column":{}}}]}}"#,
            column_of(line, "value++")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_same_file_global_value_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.c",
            "static const int global_value = 1;\nint run() { return global_value; }\n",
        )
        .build();

    let line = "int run() { return global_value; }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.c","line":2,"column":{}}}]}}"#,
            column_of(line, "global_value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "app.c", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 1, "{value}");
}

#[test]
fn cpp_bare_enum_enumerator_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
enum Mode { Ready, Done };
Mode current() { return Ready; }
"#,
        )
        .build();

    let line = "Mode current() { return Ready; }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":3,"column":{}}}]}}"#,
            column_of(line, "Ready")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Mode.Ready", "{value}");
}

#[test]
fn cpp_scoped_enum_enumerator_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
enum class PowerSaveLevel { LOW_POWER, PERFORMANCE };
PowerSaveLevel current() { return PowerSaveLevel::PERFORMANCE; }
"#,
        )
        .build();

    let line = "PowerSaveLevel current() { return PowerSaveLevel::PERFORMANCE; }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":3,"column":{}}}]}}"#,
            column_of(line, "PERFORMANCE")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "PowerSaveLevel.PERFORMANCE",
        "{value}"
    );
}

#[test]
fn cpp_bare_member_field_resolves_in_method_body() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
class Parser {
    int fp_;
    void run() {
        if (!fp_) {}
    }
};
"#,
        )
        .build();

    let line = "        if (!fp_) {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":5,"column":{}}}]}}"#,
            column_of(line, "fp_")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Parser.fp_", "{value}");
}

#[test]
fn cpp_bare_member_field_resolves_in_out_of_line_method_body() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "parser.h",
            r#"
namespace ns {
class Parser {
    int fp_;
    void run();
};
}
"#,
        )
        .file(
            "parser.cpp",
            r#"
#include "parser.h"
namespace ns {
void Parser::run() {
    if (!*fp_) {}
}
}
"#,
        )
        .build();

    let line = "    if (!*fp_) {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"parser.cpp","line":5,"column":{}}}]}}"#,
            column_of(line, "fp_")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "ns.Parser.fp_", "{value}");
}

#[test]
fn cpp_member_field_receiver_resolves_in_out_of_line_method_body() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "parser.h",
            r#"
namespace ns {
class Logger {
public:
    bool atErrorLimit() const;
};
class Parser {
    Logger& log_;
    void run();
};
}
"#,
        )
        .file(
            "parser.cpp",
            r#"
#include "parser.h"
namespace ns {
void Parser::run() {
    if (log_.atErrorLimit()) {}
}
}
"#,
        )
        .build();

    let line = "    if (log_.atErrorLimit()) {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"parser.cpp","line":5,"column":{}}}]}}"#,
            column_of(line, "atErrorLimit")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "ns.Logger.atErrorLimit",
        "{value}"
    );
}

#[test]
fn cpp_out_of_line_method_prefers_lexical_namespace_owner() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "global.h",
            r#"
class Parser {
public:
    bool wrong();
};
"#,
        )
        .file(
            "parser.h",
            r#"
namespace ns {
class Parser {
public:
    bool right();
    bool run();
};
}
"#,
        )
        .file(
            "parser.cpp",
            r#"
#include "global.h"
#include "parser.h"
namespace ns {
bool Parser::run() {
    return this->right();
}
}
"#,
        )
        .build();

    let line = "    return this->right();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"parser.cpp","line":6,"column":{}}}]}}"#,
            column_of(line, "right")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "ns.Parser.right",
        "{value}"
    );
}

#[test]
fn cpp_this_receiver_resolves_in_out_of_line_method_body() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "visitor.h",
            r#"
namespace ns {
class Visitor {
public:
    bool traverse();
    bool run();
};
}
"#,
        )
        .file(
            "visitor.cpp",
            r#"
#include "visitor.h"
namespace ns {
bool Visitor::run() {
    return this->traverse();
}
}
"#,
        )
        .build();

    let line = "    return this->traverse();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"visitor.cpp","line":5,"column":{}}}]}}"#,
            column_of(line, "traverse")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "ns.Visitor.traverse",
        "{value}"
    );
}

#[test]
fn cpp_relative_qualified_parameter_type_resolves_arrow_member() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "ast.h",
            r#"
namespace ns {
namespace ast {
class TernaryOperator {
public:
    bool condition() const;
};
}
}
"#,
        )
        .file(
            "visitor.h",
            r#"
#include "ast.h"
namespace ns {
namespace codegen {
class Visitor {
public:
    bool run(const ast::TernaryOperator* tern);
};
}
}
"#,
        )
        .file(
            "visitor.cpp",
            r#"
#include "visitor.h"
namespace ns {
namespace codegen {
bool Visitor::run(const ast::TernaryOperator* tern) {
    return tern->condition();
}
}
}
"#,
        )
        .build();

    let line = "    return tern->condition();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"visitor.cpp","line":6,"column":{}}}]}}"#,
            column_of(line, "condition")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "ns::ast.TernaryOperator.condition",
        "{value}"
    );
}

#[test]
fn cpp_relative_qualified_type_does_not_match_unrelated_suffix_namespace() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.h",
            r#"
namespace foo {
namespace bar {
class T {
public:
    bool wrong() const;
};
}
}
"#,
        )
        .file(
            "visitor.cpp",
            r#"
#include "target.h"
namespace ns {
namespace codegen {
bool run(const bar::T* value) {
    return value->wrong();
}
}
}
"#,
        )
        .build();

    let line = "    return value->wrong();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"visitor.cpp","line":6,"column":{}}}]}}"#,
            column_of(line, "wrong")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_bare_member_field_resolves_from_base_class() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
class Base {
protected:
    int fp_;
};
class Parser : public Base {
    void run() {
        if (!fp_) {}
    }
};
"#,
        )
        .build();

    let line = "        if (!fp_) {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":8,"column":{}}}]}}"#,
            column_of(line, "fp_")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Base.fp_", "{value}");
}

#[test]
fn cpp_bare_member_call_prefers_current_class_override() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
class Base {
public:
    virtual void close(bool send = true) = 0;
};
class Parser : public Base {
public:
    void close(bool send = true) override;
    void run() {
        close(false);
    }
};
void Parser::close(bool send) {}
"#,
        )
        .build();

    let line = "        close(false);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":10,"column":{}}}]}}"#,
            column_of(line, "close")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Parser.close", "{value}");
}

#[test]
fn cpp_bare_identifier_does_not_resolve_unrelated_member_field() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
class File { int fp_; };
int run() { return fp_; }
"#,
        )
        .build();

    let line = "int run() { return fp_; }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":3,"column":{}}}]}}"#,
            column_of(line, "fp_")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_static_const_struct_value_resolves_in_initializer() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.c",
            r#"
typedef struct AVClass AVClass;
typedef struct StreamOps StreamOps;

struct AVClass {
    const char *class_name;
};

struct StreamOps {
    const AVClass *priv_class;
};

static const AVClass curl_avio_class = {
    .class_name = "stream",
};

static const StreamOps stream_ops = {
    .priv_class = &curl_avio_class,
};
"#,
        )
        .build();

    let line = "    .priv_class = &curl_avio_class,";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.c","line":18,"column":{}}}]}}"#,
            column_of(line, "curl_avio_class")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "app.c", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 13, "{value}");
}

#[test]
fn cpp_out_of_line_definition_name_is_not_reference() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.cpp",
            "namespace ns { class Service { public: void run(); }; void Service::run() {} }\n",
        )
        .build();

    let line = "namespace ns { class Service { public: void run(); }; void Service::run() {} }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"target.cpp","line":1,"column":{}}}]}}"#,
            column_of(line, "run() {}")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_type_reference_does_not_resolve_to_same_named_function() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("api.h", "namespace ns { void Service(); }\n")
        .file("app.cpp", "#include \"api.h\"\nns::Service service;\n")
        .build();

    let line = "ns::Service service;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_qualified_call_does_not_cross_unrelated_namespace() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "api.h",
            "namespace ns { namespace detail { void helper() {} } }\n",
        )
        .file(
            "app.cpp",
            "#include \"api.h\"\nvoid run() { detail::helper(); }\n",
        )
        .build();

    let line = "void run() { detail::helper(); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_auto_new_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.h",
            "namespace ns { class Service { public: void run() {} }; }\n",
        )
        .file(
            "app.cpp",
            "#include \"target.h\"\nvoid handle() { auto service = new ns::Service(); service->run(); }\n",
        )
        .build();

    let line = "void handle() { auto service = new ns::Service(); service->run(); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "ns.Service.run", "{value}");
}

#[test]
fn cpp_auto_static_call_receiver_method_resolves_to_return_type() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
class Board {
public:
    static Board& GetInstance();
    void SetPowerSaveLevel();
};
void run() {
    auto& board = Board::GetInstance();
    board.SetPowerSaveLevel();
}
"#,
        )
        .build();

    let line = "    board.SetPowerSaveLevel();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":9,"column":{}}}]}}"#,
            column_of(line, "SetPowerSaveLevel")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Board.SetPowerSaveLevel",
        "{value}"
    );
}

#[test]
fn cpp_alias_pointer_receiver_resolves_underlying_type_member() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
template <class T> class shared_ptr {
public:
    T* operator->();
};
class InterfaceElement {
public:
    void getActiveOutputs();
};
class NodeDef : public InterfaceElement {};
using NodeDefPtr = shared_ptr<NodeDef>;
void run(NodeDefPtr nodeDef) {
    nodeDef->getActiveOutputs();
}
"#,
        )
        .build();

    let line = "    nodeDef->getActiveOutputs();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":13,"column":{}}}]}}"#,
            column_of(line, "getActiveOutputs")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "InterfaceElement.getActiveOutputs",
        "{value}"
    );
}

#[test]
fn cpp_template_alias_dot_receiver_does_not_unwrap_to_first_argument() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
template <class T> class vector {
public:
    int size();
};
class Node {
public:
    void visit();
};
using NodeVector = vector<Node>;
void run(NodeVector nodes) {
    nodes.visit();
}
"#,
        )
        .build();

    let line = "    nodes.visit();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":12,"column":{}}}]}}"#,
            column_of(line, "visit")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_unqualified_typo_with_angle_include_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("app.cpp", "#include <vector>\nvoid run() { typo(); }\n")
        .build();

    let line = "void run() { typo(); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "typo")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn scala_same_package_type_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Service.scala", "package app\nclass Service\n")
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { val service: Service = new Service }\n",
        )
        .build();

    let line = "class Controller { val service: Service = new Service }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "app.Service", "{value}");
}

#[test]
fn scala_constructor_call_resolves_to_primary_constructor_identity() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Service.scala",
            "package app\nclass Repository\nclass Service(repository: Repository)\nobject Service {\n  def build(repository: Repository): Service = new Service(repository)\n}\n",
        )
        .build();

    let line = "  def build(repository: Repository): Service = new Service(repository)";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Service.scala","line":5,"column":{}}}]}}"#,
            column_of(line, "Service(repository)")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Service.Service",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "app/Service.scala",
        "{value}"
    );
}

#[test]
fn scala_object_apply_call_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Factory.scala",
            "package app\nclass Service\nobject Factory { def apply(): Service = new Service }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { val service = Factory() }\n",
        )
        .build();

    let line = "class Controller { val service = Factory() }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "Factory")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Factory$.apply",
        "{value}"
    );
}

#[test]
fn scala_companion_method_call_resolves_from_type_receiver() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "example/Service.scala",
            "package example\nclass Repository\nclass Service(repository: Repository)\nobject Service { def build(repository: Repository): Service = new Service(repository) }\n",
        )
        .file(
            "example/Consumer.scala",
            "package example\nobject Consumer { def run(repository: Repository): Service = Service.build(repository) }\n",
        )
        .build();

    let line =
        "object Consumer { def run(repository: Repository): Service = Service.build(repository) }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"example/Consumer.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "build")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.Service$.build",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "example/Service.scala",
        "{value}"
    );
}

#[test]
fn scala_object_apply_call_resolves_from_constructor_like_reference() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Factory.scala",
            "package app\nclass Service\nobject Factory { def apply(): Service = new Service }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { val service = Factory() }\n",
        )
        .build();

    let line = "class Controller { val service = Factory() }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "Factory")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Factory$.apply",
        "{value}"
    );
}

#[test]
fn scala_unqualified_inherited_helper_call_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "api/RestHelper.scala",
            "package api\ntrait RestHelper { protected def collectResourceDocs(values: Seq[Int]): Seq[Int] = values }\n",
        )
        .file(
            "api/v2/Api.scala",
            r#"
package api.v2

import api.RestHelper

object Api extends RestHelper {
  def allResourceDocs: Seq[Int] = collectResourceDocs(Seq(1))
}
"#,
        )
        .build();

    let line = "  def allResourceDocs: Seq[Int] = collectResourceDocs(Seq(1))";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"api/v2/Api.scala","line":7,"column":{}}}]}}"#,
            column_of(line, "collectResourceDocs")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "api.RestHelper.collectResourceDocs",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "api/RestHelper.scala",
        "{value}"
    );
}

#[test]
fn scala_instance_member_prefers_inherited_member_over_companion_object() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Model.scala",
            "package app\nclass Base { def value: Int = 1 }\nclass Child extends Base\nobject Child { def value: Int = 2 }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { def run(child: Child): Int = child.value }\n",
        )
        .build();

    let line = "class Controller { def run(child: Child): Int = child.value }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "app.Base.value", "{value}");
}

#[test]
fn scala_source_ancestor_fallback_uses_matching_owner_not_first_simple_name() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Model.scala",
            r#"
package app

class Wrong
object Outer {
  class Child extends Wrong
}
class Base { def value: Int = 1 }
class Child extends Base
"#,
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { def run(child: Child): Int = child.value }\n",
        )
        .build();

    let line = "class Controller { def run(child: Child): Int = child.value }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "app.Base.value", "{value}");
}

#[test]
fn scala_imported_type_annotation_beats_same_package_type() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Model.scala",
            "package app\nclass Child { def local: Int = 0 }\n",
        )
        .file(
            "other/Model.scala",
            "package other\nclass Child { def value: Int = 1 }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nimport other.Child\nclass Controller { def run(child: Child): Int = child.value }\n",
        )
        .build();

    let line = "class Controller { def run(child: Child): Int = child.value }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":3,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "other.Child.value",
        "{value}"
    );
}

#[test]
fn scala_missing_imported_type_annotation_does_not_fall_back_to_same_package_type() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Model.scala",
            "package app\nclass Child { def local: Int = 0 }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nimport external.Child\nclass Controller { def run(child: Child): Int = child.local }\n",
        )
        .build();

    let line = "class Controller { def run(child: Child): Int = child.local }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":3,"column":{}}}]}}"#,
            column_of(line, "local")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn scala_nested_class_ancestor_does_not_leak_to_outer_owner() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Model.scala",
            r#"
package app

class Base { def value: Int = 1 }
class Outer {
  class Inner extends Base
}
"#,
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { def run(outer: Outer): Int = outer.value }\n",
        )
        .build();

    let line = "class Controller { def run(outer: Outer): Int = outer.value }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn scala_unqualified_member_call_beats_same_named_object_apply() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Factory.scala",
            "package app\nclass Service\nobject Factory { def apply(): Service = new Service }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { def Factory(): Int = 1; def run(): Int = Factory() }\n",
        )
        .build();

    let line = "class Controller { def Factory(): Int = 1; def run(): Int = Factory() }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "Factory() }")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Controller.Factory",
        "{value}"
    );
}

#[test]
fn scala_typed_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Service.scala",
            "package app\nclass Service { def run(): Int = 1 }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { def handle(service: Service): Int = service.run() }\n",
        )
        .build();

    let line = "class Controller { def handle(service: Service): Int = service.run() }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Service.run",
        "{value}"
    );
}

#[test]
fn scala_generic_constructor_receiver_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Scoreboard.scala",
            "package app\nclass ScoreboardInOrder[T] { def checkEmptiness(): Unit = {} }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { def handle(): Unit = { val sco = ScoreboardInOrder[String](); sco.checkEmptiness() } }\n",
        )
        .build();

    let line = "class Controller { def handle(): Unit = { val sco = ScoreboardInOrder[String](); sco.checkEmptiness() } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "checkEmptiness")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.ScoreboardInOrder.checkEmptiness",
        "{value}"
    );
}

#[test]
fn scala_constructor_parameter_field_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Context.scala",
            "package app\nclass Registry\nclass Context(val registry: Registry)\n",
        )
        .file(
            "app/Grouped.scala",
            "package app\nclass Grouped(context: Context) { val value = context.registry }\n",
        )
        .build();

    let line = "class Grouped(context: Context) { val value = context.registry }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Grouped.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "registry")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Context.registry",
        "{value}"
    );
}

#[test]
fn scala_local_receiver_shadows_constructor_parameter_fallback() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Context.scala",
            "package app\nclass Registry\nclass Context(val registry: Registry)\n",
        )
        .file(
            "app/Grouped.scala",
            "package app\nclass Grouped(context: Context) { def run(): Any = { val context = null; context.registry } }\n",
        )
        .build();

    let line = "class Grouped(context: Context) { def run(): Any = { val context = null; context.registry } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Grouped.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "registry")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn scala_modified_case_class_parameter_field_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Context.scala",
            "package app\nclass Registry\nfinal case class Context(registry: Registry)\n",
        )
        .file(
            "app/Grouped.scala",
            "package app\nclass Grouped(context: Context) { val value = context.registry }\n",
        )
        .build();

    let line = "class Grouped(context: Context) { val value = context.registry }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Grouped.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "registry")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Context.registry",
        "{value}"
    );
}

#[test]
fn scala_multiline_private_constructor_parameter_field_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/StreamContext.scala",
            "package app\nclass Registry\nprivate[app] class StreamContext(\n  val registry: Registry\n)\n",
        )
        .file(
            "app/TimeGrouped.scala",
            "package app\nprivate[app] class TimeGrouped(\n  context: StreamContext,\n  host: String\n) {\n  val value = context.registry\n}\n",
        )
        .build();

    let line = "  val value = context.registry";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/TimeGrouped.scala","line":6,"column":{}}}]}}"#,
            column_of(line, "registry")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.StreamContext.registry",
        "{value}"
    );
}

#[test]
fn scala_object_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/DataSources.scala",
            "package app\nclass DataSource\nobject DataSources { def of(source: DataSource): Int = 1 }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { val value = DataSources.of(new DataSource) }\n",
        )
        .build();

    let line = "class Controller { val value = DataSources.of(new DataSource) }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "of")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.DataSources$.of",
        "{value}"
    );
}

#[test]
fn scala_singleton_typed_receiver_method_prefers_object_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Settings.scala",
            "package app\nclass Settings { def value: Int = 0 }\nobject Settings { def value: Int = 1 }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { val settings: Settings.type = Settings; val actual = settings.value }\n",
        )
        .build();

    let line =
        "class Controller { val settings: Settings.type = Settings; val actual = settings.value }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Settings$.value",
        "{value}"
    );
}

#[test]
fn scala_stable_identifier_object_val_resolves_in_case_pattern() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "common/ApiVersion.scala",
            "package common\ntrait ApiVersion\nobject ApiVersion { val v2_1_0 = new ApiVersion {} }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nimport common.ApiVersion\nclass Controller { def docs(version: ApiVersion): Int = version match { case ApiVersion.v2_1_0 => 1; case _ => 0 } }\n",
        )
        .build();

    let line = "class Controller { def docs(version: ApiVersion): Int = version match { case ApiVersion.v2_1_0 => 1; case _ => 0 } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":3,"column":{}}}]}}"#,
            column_of(line, "v2_1_0")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "common.ApiVersion$.v2_1_0",
        "{value}"
    );
}

#[test]
fn scala_external_import_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Controller.scala",
            "package app\nimport external.Service\nclass Controller { val service: Service = ??? }\n",
        )
        .build();

    let line = "class Controller { val service: Service = ??? }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":3,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn scala_external_constructor_call_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Controller.scala",
            "package app\nimport external.Service\nclass Controller { val service = Service() }\n",
        )
        .build();

    let line = "class Controller { val service = Service() }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":3,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn scala_external_imported_function_call_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Controller.scala",
            "package app\nimport external.Helpers.make\nclass Controller { val service = make() }\n",
        )
        .build();

    let line = "class Controller { val service = make() }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":3,"column":{}}}]}}"#,
            column_of(line, "make")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn scala_local_value_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "App.scala",
            "object App { def run(): Int = { val value = 1; value } }\n",
        )
        .build();

    let line = "object App { def run(): Int = { val value = 1; value } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App.scala","line":1,"column":{}}}]}}"#,
            column_of(line, "value }")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn scala_uppercase_local_value_shadows_workspace_type() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Service.scala", "package app\nclass Service\n")
        .file(
            "app/App.scala",
            "package app\nobject App { def run(): Int = { val Service = 1; Service } }\n",
        )
        .build();

    let line = "object App { def run(): Int = { val Service = 1; Service } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/App.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "Service }")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn python_staticmethod_first_parameter_does_not_create_instance_field() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "main.py",
            r#"
class Service:
    @staticmethod
    def configure(obj):
        obj.shadow = 1

    def run(self):
        return self.shadow
"#,
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "Service.run",
                "context": "return self.shadow",
                "target": "shadow"
            }]
        })
        .to_string(),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn python_classmethod_first_parameter_does_not_create_instance_field() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "main.py",
            r#"
class Service:
    @classmethod
    def configure(cls):
        cls.shadow = 1

    def run(self):
        return self.shadow
"#,
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "Service.run",
                "context": "return self.shadow",
                "target": "shadow"
            }]
        })
        .to_string(),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn valid_local_value_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            r#"
export function run() {
  const value = 1;
  value;
}
"#,
        )
        .build();

    let line = "  value;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":4,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn unsupported_language_returns_structured_status() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("notes.txt", "helper\n")
        .build();

    let value = lookup(
        project.root(),
        r#"{"references":[{"path":"notes.txt","line":1,"column":1}]}"#,
    );

    assert_eq!(
        value["results"][0]["status"], "unsupported_language",
        "{value}"
    );
    assert!(value["results"][0]["reference"].is_null(), "{value}");
}
