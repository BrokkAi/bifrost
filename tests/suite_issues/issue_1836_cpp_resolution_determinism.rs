//! Issue #1836: C++ resolution must not depend on content-irrelevant workspace
//! differences.
//!
//! Two headers can declare the same class-template specialization -- a vendored
//! or mirrored copy of a header is the production shape. The two declarations
//! are physically distinct `CodeUnit`s that differ only in `source()`, so
//! `same_visible_symbol` treats them as interchangeable and specialization
//! selection returns whichever one comes first in the template family.
//!
//! That family was built by iterating a hash-keyed metadata map, so "first"
//! was a function of the `CodeUnit` hashes. Adding an unrelated empty header,
//! adding an unrelated comment, or simply checking the workspace out under a
//! different absolute path changes those hashes and flipped the declaring
//! header that resolution reported.
//!
//! Each variant below is the same C++ program with one content-irrelevant
//! difference; every variant must report the same definition. Each variant also
//! lands under its own temporary root, which is itself a content-irrelevant
//! difference resolution must ignore.

use crate::common::{InlineTestProject, call_search_tool_json};
use brokk_bifrost::Language;
use serde_json::{Value, json};

const DONOR: &str = r#"#pragma once
template <typename T, typename U> struct Holder { int generic; };
template <typename T> struct Holder<T, int> { int by_int; };
"#;

const CONSUMER: &str = r#"#include "alpha/holder.h"
#include "beta/holder.h"
struct Owner {
    Holder<char, int> value;
    int run() { return value.by_int; }
};
"#;

/// One content-irrelevant difference applied to the same C++ program.
struct Variant {
    label: &'static str,
    beta_comment: bool,
    unrelated_files: usize,
    reversed_declaration_order: bool,
}

fn resolved_definitions(variant: &Variant) -> Value {
    let beta = if variant.beta_comment {
        format!("{DONOR}// unrelated note about the mirrored copy\n")
    } else {
        DONOR.to_string()
    };
    let mut files: Vec<(String, String)> = vec![
        ("alpha/holder.h".to_string(), DONOR.to_string()),
        ("beta/holder.h".to_string(), beta),
        ("consumer.cc".to_string(), CONSUMER.to_string()),
    ];
    for index in 0..variant.unrelated_files {
        files.push((format!("unrelated/pad{index}.h"), String::new()));
    }
    if variant.reversed_declaration_order {
        files.reverse();
    }
    let mut builder = InlineTestProject::with_language(Language::Cpp);
    for (path, contents) in files {
        builder = builder.file(path, contents);
    }
    let project = builder.build();

    let reference = CONSUMER.find("by_int;").expect("member reference");
    let prefix = &CONSUMER[..reference];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, current)| current)
        .chars()
        .count()
        + 1;
    let args = json!({"references": [{"path": "consumer.cc", "line": line, "column": column}]})
        .to_string();
    let value = call_search_tool_json(project.root(), "get_definitions_by_location", &args);
    let result = &value["results"][0];
    assert_eq!(
        result["status"], "resolved",
        "{}: mirrored-header member must resolve: {value}",
        variant.label
    );
    json!({
        "definitions": result["definitions"]
            .as_array()
            .expect("definitions")
            .iter()
            .map(|definition| json!({
                "path": definition["path"],
                "fqn": definition["fqn"],
            }))
            .collect::<Vec<_>>(),
    })
}

#[test]
fn cpp_mirrored_specialization_resolves_to_one_declaring_header() {
    let variants = [
        Variant {
            label: "baseline",
            beta_comment: false,
            unrelated_files: 0,
            reversed_declaration_order: false,
        },
        Variant {
            label: "unrelated comment in the mirrored donor",
            beta_comment: true,
            unrelated_files: 0,
            reversed_declaration_order: false,
        },
        Variant {
            label: "one unrelated empty header",
            beta_comment: false,
            unrelated_files: 1,
            reversed_declaration_order: false,
        },
        Variant {
            label: "two unrelated empty headers",
            beta_comment: false,
            unrelated_files: 2,
            reversed_declaration_order: false,
        },
        Variant {
            label: "three unrelated empty headers",
            beta_comment: false,
            unrelated_files: 3,
            reversed_declaration_order: false,
        },
        Variant {
            label: "four unrelated empty headers",
            beta_comment: false,
            unrelated_files: 4,
            reversed_declaration_order: false,
        },
        Variant {
            label: "five unrelated empty headers",
            beta_comment: false,
            unrelated_files: 5,
            reversed_declaration_order: false,
        },
        Variant {
            label: "reversed file declaration order",
            beta_comment: false,
            unrelated_files: 0,
            reversed_declaration_order: true,
        },
        Variant {
            label: "comment plus unrelated headers",
            beta_comment: true,
            unrelated_files: 3,
            reversed_declaration_order: true,
        },
        Variant {
            label: "baseline repeated",
            beta_comment: false,
            unrelated_files: 0,
            reversed_declaration_order: false,
        },
    ];

    // The mirrored declarations are interchangeable, so the tie must break the
    // same way every time: on the declaring file, smallest first.
    let expected = json!({
        "definitions": [{"path": "alpha/holder.h", "fqn": "Holder<T, int>.by_int"}],
    });
    for variant in &variants {
        assert_eq!(
            resolved_definitions(variant),
            expected,
            "{}: resolution changed under a content-irrelevant workspace difference",
            variant.label
        );
    }
}
