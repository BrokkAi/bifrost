#[cfg(test)]
mod rust_departing_tests_tests {

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::external_call_identities_in;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::rust_tests_test_support::RUST_EXTERNAL_CALL_SOURCE as RUST_EXTERNAL_CALL_SOURCE;

    /// #2596: a multi-segment Rust callee publishes the dot-joined canonical
    /// identity an authored `std.str.from_utf8` summary is posted under, and a
    /// `use`-bound single segment reaches the same shape through the file's
    /// import binders.
    ///
    /// #3484: the identity is the activated callable's, not the spelling's, so
    /// the fixture activates the crate's declaration surface first.
    ///
    /// `has_receiver` is `false` for both. A Rust scoped path is not lowered as
    /// a call receiver the way a Java qualified static is, so an authored Rust
    /// summary must declare `"has_receiver": false`.
    #[test]
    fn a_qualified_rust_callee_publishes_a_dot_joined_external_identity() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[("lib.rs", RUST_EXTERNAL_CALL_SOURCE)],
        );
        activate_rust_declaration_pack(&fixture);
        let identities = external_call_identities_in(&fixture, "lib.rs", RUST_EXTERNAL_CALL_SOURCE);
        assert_eq!(
            identities,
            vec![
                (
                    "Path::new(text)".to_owned(),
                    Some(("std.path.Path".to_owned(), "new".to_owned(), 1, false))
                ),
                // The prelude spelling has no `use` declaration for the import
                // binder to read, so it is deliberately out of scope and names
                // no identity.
                ("String::from(text)".to_owned(), None),
                (
                    "std::str::from_utf8(bytes)".to_owned(),
                    Some(("std.str".to_owned(), "from_utf8".to_owned(), 1, false))
                ),
            ]
        );
    }

    /// A crate-root function has one owner component even when the call is
    /// written through a `use` binder. Both spellings must publish the same
    /// owner/member identity that a reviewed model uses.
    #[test]
    fn rust_crate_root_functions_publish_their_crate_identity() {
        const SOURCE: &str = r#"use regex::escape;
use html_escape::encode_text;

pub fn direct(value: &str) {
    let _ = regex::escape(value);
    let _ = html_escape::encode_text(value);
}

pub fn imported(value: &str) {
    let _ = escape(value);
    let _ = encode_text(value);
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", SOURCE)]);
        activate_rust_declaration_pack(&fixture);
        let identities = external_call_identities_in(&fixture, "lib.rs", SOURCE);

        assert_eq!(
            identities,
            vec![
                (
                    "encode_text(value)".to_owned(),
                    Some(("html_escape".to_owned(), "encode_text".to_owned(), 1, false,))
                ),
                (
                    "escape(value)".to_owned(),
                    Some(("regex".to_owned(), "escape".to_owned(), 1, false))
                ),
                (
                    "html_escape::encode_text(value)".to_owned(),
                    Some(("html_escape".to_owned(), "encode_text".to_owned(), 1, false,))
                ),
                (
                    "regex::escape(value)".to_owned(),
                    Some(("regex".to_owned(), "escape".to_owned(), 1, false))
                ),
            ]
        );
    }

    /// The reviewed `std` declaration surface the #2596 fixture's calls resolve
    /// against: the crate root, the two owner paths, and one receiverless
    /// callable of the written arity on each.
    fn activate_rust_declaration_pack(fixture: &AnalyzerFixture) {
        let pack_json = serde_json::json!({
            "schema_version": 2,
            "pack_id": "fixture.rust-std-declarations",
            "version": "1.0.0",
            "producer": { "name": "rust-dispatch-fixture", "version": "1.0.0" },
            "language": "rust",
            "ecosystem": "cargo",
            "compatibility": { "bifrost": "*", "toolchains": [] },
            "provenance": { "source": "fixture" },
            "license": "NOASSERTION",
            "completeness": "complete",
            "safety": { "generated_code_only": false, "review_required": false },
            "shards": [{
                "id": "declarations.rust-fixture",
                "activation": [{}],
                "payload": {
                    "kind": "declaration_facts",
                    "types": [
                        rust_fixture_type("std", "module"),
                        rust_fixture_type("std.str", "module"),
                        rust_fixture_type("std.path", "module"),
                        rust_fixture_type("std.path.Path", "struct"),
                        rust_fixture_type("regex", "module"),
                        rust_fixture_type("html_escape", "module")
                    ],
                    "members": [
                        rust_fixture_member("std.str", "from_utf8"),
                        rust_fixture_member("std.path.Path", "new"),
                        rust_fixture_member("regex", "escape"),
                        rust_fixture_member("html_escape", "encode_text")
                    ],
                    "relations": []
                }
            }]
        });
        brokk_bifrost_analysis::test_support::activate_rust_declaration_pack(
            fixture.analyzer.analyzer(),
            "fixture.rust-std-declarations",
            &pack_json,
        );
    }

    fn rust_fixture_type(name: &str, type_kind: &str) -> serde_json::Value {
        serde_json::json!({
            "id": format!("type.rust-fixture.{}", rust_fixture_identifier(name)),
            "name": name,
            "type_kind": type_kind,
            "visibility": "public",
            "locator": {
                "kind": "artifact",
                "path": "library/std/src/lib.rs",
                "symbol": name
            }
        })
    }

    fn rust_fixture_member(owner: &str, member: &str) -> serde_json::Value {
        serde_json::json!({
            "id": format!("member.rust-fixture.{}.{member}", rust_fixture_identifier(owner)),
            "owner": format!("type.rust-fixture.{}", rust_fixture_identifier(owner)),
            "name": member,
            "member_kind": "method",
            "visibility": "public",
            "is_static": true,
            "callable_family_complete": true,
            "signature": {
                "parameters": [{
                    "name": "value",
                    "type": { "kind": "named", "name": "untyped" }
                }]
            },
            "locator": {
                "kind": "artifact",
                "path": "library/std/src/lib.rs",
                "symbol": format!("{owner}.{member}")
            }
        })
    }

    /// Stable ids in a compiled pack admit lowercase ASCII alphanumerics and
    /// `-`, so a fixture path segment loses its Rust casing and separators the
    /// same way the reviewed web-network pack writes `std-net-tcpstream`.
    fn rust_fixture_identifier(name: &str) -> String {
        name.to_lowercase().replace('.', "-")
    }
}
