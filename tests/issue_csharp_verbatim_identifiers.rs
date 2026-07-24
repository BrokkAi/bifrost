//! Regression coverage for C# verbatim-identifier (`@name`) normalization on the
//! get-definition / reference-resolution side.
//!
//! C# lets any identifier be written with a leading `@` escape (`@class`,
//! `@Compute`); the two spellings denote the same symbol. The declaration side
//! already strips the `@` when it builds short/fq names, so a usage written with
//! the `@` escape must strip it too or it can never match its declaration. Before
//! the shared `node_ident_text` sigil normalization this reference-side strip was
//! missing (the same inconsistency class as Rust's `r#`), so a verbatim-spelled
//! call failed to resolve. This test fails before that fix and passes after it.

mod common;

use common::{InlineTestProject, call_search_tool_json};
use serde_json::Value;

fn lookup(root: &std::path::Path, args: &str) -> Value {
    call_search_tool_json(root, "get_definitions_by_location", args)
}

fn column_of(line: &str, needle: &str) -> usize {
    line.find(needle).expect("needle in line") + 1
}

#[test]
fn csharp_verbatim_identifier_member_call_resolves_to_plain_declaration() {
    let project = InlineTestProject::with_language(brokk_bifrost::Language::CSharp)
        .file(
            "Lib/Service.cs",
            "namespace Lib { public class Service { public void Compute() {} } }\n",
        )
        .file(
            "App/Controller.cs",
            "using Lib;\nnamespace App { public class Controller { public void Handle(Service service) { service.@Compute(); } } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { public void Handle(Service service) { service.@Compute(); } } }";
    // Point the cursor inside the `@Compute` verbatim identifier token.
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "@Compute") + 1
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Lib.Service.Compute",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "Lib/Service.cs",
        "{value}"
    );
}
