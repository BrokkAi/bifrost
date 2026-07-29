//! Regression coverage for issue #1218: a C# using-boundary failure message
//! must never name an indexed candidate as "not indexed" — the same
//! invariant #1126/#1089/#1174 already guard, applied along the
//! declaration-*kind* axis instead of shadowing/naming/language.
//!
//! Real-world shape (Newtonsoft.Json, tier-5 fuzzer): `JsonSerializer`
//! declares a deprecated `Binder` property whose signature reads
//! `SerializationBinder Binder { get; set; }`. The property's *type*,
//! `SerializationBinder`, is the BCL's `System.Runtime.Serialization`
//! abstract class — genuinely external, not indexed — but `JsonSerializer`
//! also separately declares a *member* named `SerializationBinder`. Both
//! share the bare spelling `SerializationBinder`, so when the type reference
//! fails resolution, the pre-fix code named it in a "not indexed" using-
//! boundary claim, even though the workspace's index plainly contains a
//! declaration spelled exactly that way in the very same file.
//!
//! `tests/common/inline_project.rs`'s `InlineTestProject` builds a minimal
//! repro of the same collision (a property's declared type coincides with an
//! unrelated sibling member's name), a negative control where the type
//! reference is genuinely external with no collision anywhere in the
//! workspace, and a control where the type reference is itself a real,
//! resolvable workspace type.

mod common;

use brokk_bifrost::Language;
use common::{InlineTestProject, definition_reference_status};

const JSON_SERIALIZER_SHAPE: &str = "using System.Runtime.Serialization;\n\nnamespace Newtonsoft.Json\n{\n    public class JsonSerializer\n    {\n        public SerializationBinder Binder { get; set; }\n\n        public object SerializationBinder { get; set; }\n\n        public StreamingContext Context { get; set; }\n\n        public CustomBinder Custom { get; set; }\n    }\n\n    public class CustomBinder\n    {\n    }\n}\n";

fn project() -> common::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::CSharp)
        .file(
            "Src/Newtonsoft.Json/JsonSerializer.cs",
            JSON_SERIALIZER_SHAPE,
        )
        .build()
}

fn status_and_message(
    project: &common::BuiltInlineTestProject,
    symbol: &str,
    context: &str,
    target: &str,
) -> (String, String) {
    let args = serde_json::json!({
        "references": [{ "symbol": symbol, "context": context, "target": target }]
    })
    .to_string();
    let result = common::call_tool(project, "get_definitions_by_reference", &args);
    let status = result["results"][0]["status"]
        .as_str()
        .unwrap_or_else(|| panic!("expected a status string, got {result}"))
        .to_string();
    let message = result["results"][0]["diagnostics"][0]["message"]
        .as_str()
        .unwrap_or("")
        .to_string();
    (status, message)
}

/// The renamed-member / kind-collision shape: `Binder`'s declared type
/// `SerializationBinder` fails to resolve as a C# type (it names the BCL's
/// external `System.Runtime.Serialization.SerializationBinder`), but the
/// exact identifier `SerializationBinder` is indexed as a sibling *property*
/// on the very same owner. The failure message must name that indexed
/// declaration honestly, never claim it "crosses a boundary not indexed".
#[test]
fn jsonserializer_binder_type_reference_does_not_claim_indexed_candidate_unindexed() {
    let project = project();
    let (status, message) = status_and_message(
        &project,
        "Newtonsoft.Json.JsonSerializer.Binder",
        "public SerializationBinder Binder { get; set; }",
        "SerializationBinder",
    );

    assert_eq!(
        status, "no_definition",
        "must not be a boundary claim: {message}"
    );
    assert!(
        !message.to_ascii_lowercase().contains("not indexed"),
        "message must not claim non-indexing for an indexed name: {message}"
    );
    assert!(
        !message.to_ascii_lowercase().contains("boundary"),
        "message must not be a using-boundary claim: {message}"
    );
    assert!(
        message.contains("SerializationBinder"),
        "message must still name the indexed candidate: {message}"
    );
    assert!(
        message.contains("JsonSerializer.SerializationBinder"),
        "message must name the indexed declaration's fq: {message}"
    );
}

/// Negative control: `Context`'s declared type `StreamingContext` is also
/// genuinely external (same `System.Runtime.Serialization` shape), but no
/// declaration named `StreamingContext` exists anywhere in the workspace.
/// The boundary claim must still fire — the fix must not blanket-suppress
/// every using-boundary claim, only the ones naming an indexed candidate.
#[test]
fn jsonserializer_context_type_reference_stays_a_boundary_claim() {
    let project = project();
    let (status, message) = status_and_message(
        &project,
        "Newtonsoft.Json.JsonSerializer.Context",
        "public StreamingContext Context { get; set; }",
        "StreamingContext",
    );

    assert_eq!(status, "unresolvable_import_boundary", "message: {message}");
    assert!(
        message.to_ascii_lowercase().contains("boundary"),
        "message: {message}"
    );
    assert!(message.contains("StreamingContext"), "message: {message}");
}

/// Control: a type reference that resolves normally must keep resolving
/// normally — the fix must not turn a real hit into a diagnostic.
#[test]
fn jsonserializer_custom_type_reference_resolves_normally() {
    let project = project();
    let status = definition_reference_status(
        &project,
        "Newtonsoft.Json.JsonSerializer.Custom",
        "public CustomBinder Custom { get; set; }",
        "CustomBinder",
    );
    assert_eq!(status, "resolved");
}
