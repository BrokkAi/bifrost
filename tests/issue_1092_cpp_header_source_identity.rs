mod common;

use brokk_bifrost::{Language, SearchToolsService};
use common::{BuiltInlineTestProject, InlineTestProject};
use serde_json::Value;

fn open_service(project: &BuiltInlineTestProject) -> SearchToolsService {
    SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).expect("service")
}

fn call(service: &SearchToolsService, tool: &str, arguments: Value) -> Value {
    let payload = service
        .call_tool_json(tool, &arguments.to_string())
        .expect("tool call");
    serde_json::from_str(&payload).expect("valid JSON")
}

fn source_blocks(value: &Value) -> &[Value] {
    value["sources"].as_array().expect("sources")
}

#[test]
fn c_header_and_body_share_identity_while_anchors_remain_physical() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("include/api.h", "int c_compute(int header_name);\n")
        .file(
            "src/api.c",
            "#include \"../include/api.h\"\nint c_compute(int body_name) { return body_name; }\n",
        )
        .build();
    let service = open_service(&project);

    let bare = call(
        &service,
        "get_symbol_sources",
        serde_json::json!({"symbols": ["c_compute"]}),
    );
    let bare_sources = source_blocks(&bare);
    assert_eq!(1, bare_sources.len(), "{bare}");
    assert_eq!("src/api.c", bare_sources[0]["path"]);
    assert_eq!("definition", bare_sources[0]["occurrence_role"]);
    assert_eq!(
        "include/api.h#c_compute",
        bare_sources[0]["canonical_selector"]
    );

    let header = call(
        &service,
        "get_symbol_sources",
        serde_json::json!({"symbols": ["include/api.h#c_compute"]}),
    );
    assert_eq!("include/api.h", source_blocks(&header)[0]["path"]);
    assert_eq!("declaration", source_blocks(&header)[0]["occurrence_role"]);
}

#[test]
fn bare_cpp_overload_set_prefers_definitions_and_anchors_keep_occurrences() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "include/api.h",
            r#"#pragma once
int compute(int header_name);
int compute(double header_name);
int declared_only(int value);
inline int header_inline(int value) { return value; }
"#,
        )
        .file(
            "src/api.cpp",
            r#"#include "../include/api.h"
int compute(int definition_name) { return definition_name; }
int compute(double definition_name) { return static_cast<int>(definition_name); }
"#,
        )
        .build();
    let service = open_service(&project);

    let bare = call(
        &service,
        "get_symbol_sources",
        serde_json::json!({"symbols": ["compute"]}),
    );
    assert!(
        bare["ambiguous"].as_array().is_none_or(Vec::is_empty),
        "{bare}"
    );
    let bare_sources = source_blocks(&bare);
    assert_eq!(2, bare_sources.len(), "{bare}");
    assert!(bare_sources.iter().all(|source| {
        source["path"] == "src/api.cpp"
            && source["occurrence_role"] == "definition"
            && source["canonical_selector"] == "include/api.h#compute"
    }));

    let header = call(
        &service,
        "get_symbol_sources",
        serde_json::json!({"symbols": ["include/api.h#compute"]}),
    );
    let header_sources = source_blocks(&header);
    assert_eq!(2, header_sources.len(), "{header}");
    assert!(header_sources.iter().all(|source| {
        source["path"] == "include/api.h"
            && source["occurrence_role"] == "declaration"
            && source["canonical_selector"] == "include/api.h#compute"
    }));

    let implementation = call(
        &service,
        "get_symbol_sources",
        serde_json::json!({"symbols": ["src/api.cpp#compute"]}),
    );
    let implementation_sources = source_blocks(&implementation);
    assert_eq!(2, implementation_sources.len(), "{implementation}");
    assert!(implementation_sources.iter().all(|source| {
        source["path"] == "src/api.cpp"
            && source["occurrence_role"] == "definition"
            && source["canonical_selector"] == "include/api.h#compute"
    }));

    let declaration_only = call(
        &service,
        "get_symbol_sources",
        serde_json::json!({"symbols": ["declared_only"]}),
    );
    let declaration_sources = source_blocks(&declaration_only);
    assert_eq!(1, declaration_sources.len(), "{declaration_only}");
    assert_eq!("include/api.h", declaration_sources[0]["path"]);
    assert_eq!("declaration", declaration_sources[0]["occurrence_role"]);
    assert_eq!(
        "include/api.h#declared_only",
        declaration_sources[0]["canonical_selector"]
    );

    let inline_definition = call(
        &service,
        "get_symbol_sources",
        serde_json::json!({"symbols": ["header_inline"]}),
    );
    let inline_sources = source_blocks(&inline_definition);
    assert_eq!(1, inline_sources.len(), "{inline_definition}");
    assert_eq!("include/api.h", inline_sources[0]["path"]);
    assert_eq!("definition", inline_sources[0]["occurrence_role"]);

    let summary = call(
        &service,
        "get_summaries",
        serde_json::json!({"targets": ["include/api.h"]}),
    );
    let elements = summary["summaries"][0]["elements"]
        .as_array()
        .expect("summary elements");
    assert!(
        elements.iter().any(|element| {
            element["symbol"] == "compute" && element["path"] == "include/api.h"
        }),
        "{summary}"
    );

    // Reopening the persisted analyzer must preserve both occurrence metadata
    // and the declaration-anchored canonical identity.
    drop(service);
    let reopened = open_service(&project);
    let persisted = call(
        &reopened,
        "get_symbol_sources",
        serde_json::json!({"symbols": ["compute"]}),
    );
    assert_eq!(bare["sources"], persisted["sources"], "{persisted}");
}

#[test]
fn cpp_identity_does_not_merge_internal_unrelated_or_multi_body_definitions() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("include/api.h", "int duplicated(int value);\n")
        .file(
            "src/first.cpp",
            "#include \"../include/api.h\"\nint duplicated(int value) { return value; }\nstatic int local(int value) { return value; }\n",
        )
        .file(
            "src/second.cpp",
            "#include \"../include/api.h\"\nint duplicated(int value) { return value + 1; }\nstatic int local(int value) { return value + 1; }\n",
        )
        .file(
            "copies/first.cpp",
            "int unrelated(int value) { return value; }\n",
        )
        .file(
            "copies/second.cpp",
            "int unrelated(int value) { return value + 1; }\n",
        )
        .build();
    let service = open_service(&project);

    for symbol in ["duplicated", "local", "unrelated"] {
        let value = call(
            &service,
            "get_symbol_sources",
            serde_json::json!({"symbols": [symbol]}),
        );
        assert!(
            !value["ambiguous"].as_array().is_none_or(Vec::is_empty),
            "{symbol}: {value}"
        );
        assert!(
            value["sources"].as_array().is_none_or(Vec::is_empty),
            "{symbol}: {value}"
        );
    }
}

#[test]
fn cpp_same_file_anchor_keeps_both_occurrences_while_bare_prefers_body() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "same.cpp",
            "int same_file(int value);\nint same_file(int renamed) { return renamed; }\n",
        )
        .build();
    let service = open_service(&project);

    let bare = call(
        &service,
        "get_symbol_sources",
        serde_json::json!({"symbols": ["same_file"]}),
    );
    let bare_sources = source_blocks(&bare);
    assert_eq!(1, bare_sources.len(), "{bare}");
    assert_eq!("definition", bare_sources[0]["occurrence_role"]);

    let anchored = call(
        &service,
        "get_symbol_sources",
        serde_json::json!({"symbols": ["same.cpp#same_file"]}),
    );
    let anchored_sources = source_blocks(&anchored);
    assert_eq!(2, anchored_sources.len(), "{anchored}");
    assert!(
        anchored_sources
            .iter()
            .any(|source| source["occurrence_role"] == "declaration"),
        "{anchored}"
    );
    assert!(
        anchored_sources
            .iter()
            .any(|source| source["occurrence_role"] == "definition"),
        "{anchored}"
    );
    assert!(
        anchored_sources
            .iter()
            .all(|source| { source["canonical_selector"] == "same.cpp#same_file" })
    );
}

#[test]
fn cpp_definition_candidates_publish_the_same_canonical_identity() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("include/api.h", "int compute(int value);\n")
        .file(
            "src/api.cpp",
            "#include \"../include/api.h\"\nint compute(int renamed) { return renamed; }\n",
        )
        .file(
            "src/main.cpp",
            "#include \"../include/api.h\"\nint main() { return compute(1); }\n",
        )
        .build();
    let service = open_service(&project);
    let definitions = call(
        &service,
        "get_definitions_by_location",
        serde_json::json!({
            "references": [{
                "path": "src/main.cpp",
                "line": 2,
                "column": 21
            }]
        }),
    );
    let candidate = &definitions["results"][0]["definitions"][0];
    assert_eq!(
        "resolved", definitions["results"][0]["status"],
        "{definitions}"
    );
    assert_eq!("src/api.cpp", candidate["path"], "{definitions}");
    assert_eq!("definition", candidate["occurrence_role"], "{definitions}");
    assert_eq!(
        "include/api.h#compute", candidate["canonical_selector"],
        "{definitions}"
    );
}

#[test]
fn large_cpp_overload_family_uses_one_canonical_identity() {
    const OVERLOADS: usize = 48;
    let mut header = String::new();
    let mut implementation = "#include \"../include/api.h\"\n".to_string();
    for index in 0..OVERLOADS {
        header.push_str(&format!("int generated(Type{index} value);\n"));
        implementation.push_str(&format!(
            "int generated(Type{index} value) {{ return {index}; }}\n"
        ));
    }
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("include/api.h", header)
        .file("src/api.cpp", implementation)
        .build();
    let service = open_service(&project);

    let bare = call(
        &service,
        "get_symbol_sources",
        serde_json::json!({"symbols": ["generated"]}),
    );
    let sources = source_blocks(&bare);
    assert_eq!(OVERLOADS, sources.len(), "{bare}");
    assert!(sources.iter().all(|source| {
        source["path"] == "src/api.cpp"
            && source["occurrence_role"] == "definition"
            && source["canonical_selector"] == "include/api.h#generated"
    }));
}
