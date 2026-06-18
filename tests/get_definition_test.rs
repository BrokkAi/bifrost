mod common;

use brokk_bifrost::{Language, SearchToolsService};
use common::InlineTestProject;
use serde_json::Value;

fn lookup(root: &std::path::Path, args: &str) -> Value {
    let service = SearchToolsService::new_without_semantic_index(root.to_path_buf())
        .expect("failed to build searchtools service");
    let payload = service
        .call_tool_json("get_definition", args)
        .expect("get_definition call failed");
    serde_json::from_str(&payload).expect("get_definition returned invalid JSON")
}

fn column_of(line: &str, needle: &str) -> usize {
    line.find(needle).expect("needle in line") + 1
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
    assert_eq!(result["reference"]["text"], "format_value", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "format_value", "{value}");
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
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        0,
        "{value}"
    );
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
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", "def run():\n    helper()\n")
        .build();

    let value = lookup(
        project.root(),
        r#"{"references":[{"path":"app.py","line":2,"column":5}]}"#,
    );

    assert_eq!(
        value["results"][0]["status"], "unsupported_language",
        "{value}"
    );
}
