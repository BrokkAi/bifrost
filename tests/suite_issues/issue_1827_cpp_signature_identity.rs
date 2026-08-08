//! #1827: a C++ declaration and its out-of-line definition are one entity even
//! when the parameter list is spelled with different whitespace, and even when
//! only one of them spells a top-level `const` on a parameter.

use crate::common::{BuiltInlineTestProject, InlineTestProject};
use brokk_bifrost::{Language, SearchToolsService};
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

fn sources_for(project: &BuiltInlineTestProject, symbol: &str) -> Value {
    let service = open_service(project);
    call(
        &service,
        "get_symbol_sources",
        serde_json::json!({ "symbols": [symbol] }),
    )
}

#[test]
fn multiline_parameter_list_keeps_the_trailing_const_of_the_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "widget.h",
            r#"#pragma once
class Widget {
public:
    bool prepare(int settings, int supprs) const;
};
"#,
        )
        .file(
            "widget.cpp",
            r#"#include "widget.h"
bool
Widget::prepare (int settings,
                 int supprs) const
{
    return settings + supprs > 0;
}
"#,
        )
        .build();

    let sources = sources_for(&project, "Widget.prepare");
    let blocks = source_blocks(&sources);
    assert_eq!(1, blocks.len(), "{sources}");
    assert_eq!("widget.cpp", blocks[0]["path"], "{sources}");
    assert_eq!("definition", blocks[0]["occurrence_role"], "{sources}");
    assert_eq!(
        "widget.h#Widget.prepare", blocks[0]["canonical_selector"],
        "{sources}"
    );
}

#[test]
fn top_level_parameter_const_does_not_split_declaration_from_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "widget.h",
            r#"#pragma once
class Widget {
public:
    bool prepare(const int settings, const int supprs);
};
"#,
        )
        .file(
            "widget.cpp",
            r#"#include "widget.h"
bool Widget::prepare(int settings, int supprs) {
    return settings + supprs > 0;
}
"#,
        )
        .build();

    let sources = sources_for(&project, "Widget.prepare");
    let blocks = source_blocks(&sources);
    assert_eq!(1, blocks.len(), "{sources}");
    assert_eq!("widget.cpp", blocks[0]["path"], "{sources}");
    assert_eq!("definition", blocks[0]["occurrence_role"], "{sources}");
    assert_eq!(
        "widget.h#Widget.prepare", blocks[0]["canonical_selector"],
        "{sources}"
    );
}

#[test]
fn const_and_non_const_member_overloads_stay_separate_entities() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "widget.h",
            r#"#pragma once
class Widget {
public:
    int* slot(int index);
    const int* slot(int index) const;
};
"#,
        )
        .file(
            "widget.cpp",
            r#"#include "widget.h"
int* Widget::slot(int index) { return nullptr; }
const int* Widget::slot(int index) const { return nullptr; }
"#,
        )
        .build();

    let sources = sources_for(&project, "Widget.slot");
    let blocks = source_blocks(&sources);
    assert_eq!(2, blocks.len(), "{sources}");
    assert!(
        blocks
            .iter()
            .all(|block| block["path"] == "widget.cpp" && block["occurrence_role"] == "definition"),
        "{sources}"
    );
}

#[test]
fn pointee_const_overloads_stay_separate_entities() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "widget.h",
            r#"#pragma once
class Widget {
public:
    void take(const int* value);
    void take(int* value);
};
"#,
        )
        .file(
            "widget.cpp",
            r#"#include "widget.h"
void Widget::take(const int* value) {}
void Widget::take(int* value) {}
"#,
        )
        .build();

    let sources = sources_for(&project, "Widget.take");
    let blocks = source_blocks(&sources);
    assert_eq!(2, blocks.len(), "{sources}");
    assert!(
        blocks
            .iter()
            .all(|block| block["path"] == "widget.cpp" && block["occurrence_role"] == "definition"),
        "{sources}"
    );
}
