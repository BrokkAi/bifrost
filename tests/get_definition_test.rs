mod common;

use brokk_bifrost::{Language, SearchToolsService};
use common::InlineTestProject;
use serde_json::{Value, json};

fn lookup(root: &std::path::Path, args: &str) -> Value {
    let service = SearchToolsService::new_without_semantic_index(root.to_path_buf())
        .expect("failed to build searchtools service");
    let payload = service
        .call_tool_json("get_definition_by_location", args)
        .expect("get_definition_by_location call failed");
    serde_json::from_str(&payload).expect("get_definition_by_location returned invalid JSON")
}

fn lookup_reference(root: &std::path::Path, args: &str) -> Value {
    let service = SearchToolsService::new_without_semantic_index(root.to_path_buf())
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
    assert_eq!(result["definition"]["fqn"], "format_value", "{value}");
    assert_eq!(result["definition"]["path"], "util.rs", "{value}");
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
    assert_eq!(result["definition"]["path"], "util.rs", "{value}");
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
    assert_eq!(result["definition"]["path"], "util.rs", "{value}");
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
    assert!(result["definition"].is_null(), "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "ambiguous_reference_target",
        "{value}"
    );
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
    assert_eq!(result["definition"]["path"], "util.rs", "{value}");
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
    assert!(result["definition"].is_null(), "{value}");
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
    assert!(value["results"][0]["definition"].is_null(), "{value}");
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
    assert!(value["results"][0]["definition"].is_null(), "{value}");
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
        value["results"][0]["definition"]["path"], "tests/helper.rs",
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
    assert_eq!(result["definition"]["fqn"], "helper", "{value}");
    assert_eq!(result["definition"]["path"], "util.ts", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "helper", "{value}");
    assert_eq!(result["definition"]["path"], "src/util.ts", "{value}");
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
    assert_eq!(result["definition"]["path"], "util.js", "{value}");
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
        result["definition"]["fqn"], "example.com/app/sub.Helper",
        "{value}"
    );
    assert_eq!(result["definition"]["path"], "sub/sub.go", "{value}");
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
        result["definition"]["fqn"], "example.com/app/sub.Helper",
        "{value}"
    );
    assert_eq!(result["definition"]["path"], "sub/sub.go", "{value}");
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
    assert!(value["results"][0]["definition"].is_null(), "{value}");
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
    assert!(value["results"][0]["definition"].is_null(), "{value}");
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
    assert_eq!(result["definition"]["fqn"], "pkg.Target", "{value}");
    assert_eq!(result["definition"]["path"], "pkg/Target.java", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "pkg.Target.run", "{value}");
    assert_eq!(result["definition"]["path"], "pkg/Target.java", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "pkg.Target.run", "{value}");
    assert_eq!(result["definition"]["path"], "pkg/Target.java", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "pkg.Util.format", "{value}");
    assert_eq!(result["definition"]["path"], "pkg/Util.java", "{value}");
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
        result["definition"]["fqn"], "pkg.BaseUtil.isEmpty",
        "{value}"
    );
    assert_eq!(result["definition"]["path"], "pkg/BaseUtil.java", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "app.Holder.value", "{value}");
    assert_eq!(result["definition"]["path"], "app/Holder.java", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "App.Service", "{value}");
    assert_eq!(result["definition"]["path"], "src/Service.php", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "App.render_view", "{value}");
    assert_eq!(result["definition"]["path"], "src/helpers.php", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "App.Service.run", "{value}");
    assert_eq!(result["definition"]["path"], "src/Service.php", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "App.Service", "{value}");
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
        result["definition"]["fqn"], "App.BaseController.run",
        "{value}"
    );
    assert_eq!(
        result["definition"]["path"], "src/BaseController.php",
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
    assert_eq!(result["definition"]["fqn"], "pkg.util.helper", "{value}");
    assert_eq!(result["definition"]["path"], "pkg/util.py", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "pkg.util.helper", "{value}");
    assert_eq!(result["definition"]["path"], "pkg/util.py", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "pkg.util", "{value}");
    assert_eq!(result["definition"]["path"], "pkg/util.py", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "pkg.util.helper", "{value}");
    assert_eq!(result["definition"]["path"], "pkg/util.py", "{value}");
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
        result["definition"]["fqn"], "service.Service.run",
        "{value}"
    );
    assert_eq!(result["definition"]["path"], "service.py", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "service.Base.run", "{value}");
    assert_eq!(result["definition"]["path"], "service.py", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "Lib.Service", "{value}");
    assert_eq!(result["definition"]["path"], "Lib/Service.cs", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "Lib.Service.Run", "{value}");
    assert_eq!(result["definition"]["path"], "Lib/Service.cs", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "App.Controller.Run", "{value}");
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
    assert!(value["results"][0]["definition"].is_null(), "{value}");
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
    assert_eq!(result["definition"]["fqn"], "ns.Service", "{value}");
    assert_eq!(result["definition"]["path"], "target.h", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "ns.Service.run", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "ns::detail.helper", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "ns.Service.run", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "app.Service", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "app.Factory$.apply", "{value}");
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
    assert_eq!(result["definition"]["fqn"], "app.Factory$.apply", "{value}");
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
        result["definition"]["fqn"], "app.Controller.Factory",
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
    assert_eq!(result["definition"]["fqn"], "app.Service.run", "{value}");
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
        result["definition"]["fqn"], "app.Context.registry",
        "{value}"
    );
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
        result["definition"]["fqn"], "app.Context.registry",
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
        result["definition"]["fqn"], "app.StreamContext.registry",
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
        result["definition"]["fqn"], "app.DataSources$.of",
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
        result["definition"]["fqn"], "app.Settings$.value",
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
