#[cfg(test)]
mod rust_departing_tests_tests {
    use brokk_bifrost_analysis::analyzer::QueryScope;

    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchBoundaryKind;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationService;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::ExactCallLocation;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::ResolverOwnedExternalCalleeIdentity;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::test_support::call_span;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::test_support::generous_limits;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    /// The reviewed Rust declaration surface for
    /// `std::net::TcpStream::connect`: the crate root, its two owner paths,
    /// and one receiverless callable of the written arity. It mirrors the
    /// shipped web-network pack, which is what an authored network summary is
    /// keyed by.
    fn activate_rust_connect_declaration_pack(fixture: &AnalyzerFixture) {
        let pack_id = "fixture.rust-std-connect-declarations";
        let pack_json = serde_json::json!({
            "schema_version": 2,
            "pack_id": pack_id,
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
                        {
                            "id": "type.rust-fixture.std",
                            "name": "std",
                            "type_kind": "module",
                            "visibility": "public",
                            "locator": {
                                "kind": "artifact",
                                "path": "library/std/src/lib.rs",
                                "symbol": "std"
                            }
                        },
                        {
                            "id": "type.rust-fixture.std-net",
                            "name": "std.net",
                            "type_kind": "module",
                            "visibility": "public",
                            "locator": {
                                "kind": "artifact",
                                "path": "library/std/src/net/mod.rs",
                                "symbol": "std.net"
                            }
                        },
                        {
                            "id": "type.rust-fixture.std-net-tcpstream",
                            "name": "std.net.TcpStream",
                            "type_kind": "struct",
                            "visibility": "public",
                            "locator": {
                                "kind": "artifact",
                                "path": "library/std/src/net/tcp.rs",
                                "symbol": "std.net.TcpStream"
                            }
                        }
                    ],
                    "members": [{
                        "id": "member.rust-fixture.std-net-tcpstream.connect",
                        "owner": "type.rust-fixture.std-net-tcpstream",
                        "name": "connect",
                        "member_kind": "method",
                        "visibility": "public",
                        "is_static": true,
                        "callable_family_complete": true,
                        "signature": {
                            "parameters": [{
                                "name": "addr",
                                "type": { "kind": "named", "name": "untyped" }
                            }]
                        },
                        "locator": {
                            "kind": "artifact",
                            "path": "library/std/src/net/tcp.rs",
                            "symbol": "std.net.TcpStream.connect"
                        }
                    }],
                    "relations": []
                }
            }]
        });
        brokk_bifrost_analysis::test_support::activate_rust_declaration_pack(
            fixture.analyzer.analyzer(),
            pack_id,
            &pack_json,
        );
    }

    /// #3484: the imported spelling (`use std::net::TcpStream;` then
    /// `TcpStream::connect(addr)`) publishes the same evidence pair the
    /// written-out `std::net::TcpStream::connect(addr)` route publishes. The
    /// exact callable proof and the resolver-owned owner/member identity
    /// travel together through `resolve_call_target_batch_with_source` and the
    /// common dispatch path, because a matching summary is behavior attached
    /// to a callable rather than to the spelling that named it. An expansion
    /// that only translated a name would leave both fields empty and the
    /// reviewed summary unbound.
    #[test]
    fn rust_imported_external_member_publishes_exact_proof_and_identity() {
        let source = "use std::net::TcpStream;\n\npub fn total() {\n    let _connection = \
                      TcpStream::connect(\"127.0.0.1:9\");\n}\n";
        let call = "TcpStream::connect(\"127.0.0.1:9\")";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        activate_rust_connect_declaration_pack(&fixture);
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "lib.rs"),
                call_span: call_span(source, call),
            },
            Arc::from(source),
            generous_limits(),
            None,
        );

        assert!(
            lookup.targets.is_empty(),
            "an external declaration is not a workspace target: {lookup:#?}"
        );
        let proof = lookup
            .exact_external_call
            .as_ref()
            .unwrap_or_else(|| panic!("the imported call must carry its exact proof: {lookup:#?}"));
        assert_eq!(proof.canonical_callee(), "std::net::TcpStream::connect");
        assert_eq!(proof.parameter_count(), 1);
        assert!(
            !proof.has_receiver(),
            "an associated function of the owner takes no receiver: {proof:#?}"
        );
        assert_eq!(
            lookup.boundaries,
            vec![CallDispatchBoundaryKind::External {
                callee_text: Some("std::net::TcpStream::connect".into()),
                normalized_static_owner: None,
                external_callee_identity: Some(ResolverOwnedExternalCalleeIdentity::new(
                    Language::Rust,
                    "std.net.TcpStream",
                    "connect",
                )),
            }],
            "the imported spelling and the written spelling publish one identity: {lookup:#?}"
        );
    }
}
