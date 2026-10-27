pub use brokk_bifrost_semantic::analyzer::semantic_model::artifact::*;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AnonymousCallableIdentity;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::ArtifactEncoding;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::ArtifactError;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredAtomicOperation;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredClassDecoratorIdentity;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredClassDecoratorKeyword;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredConcurrencyEffect;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredConditionalIndirectWrite;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredIndirectWriteTarget;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredLockCondition;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredLockMode;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredNormalReturnTypeRefinement;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredOperationPrecondition;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredPayload;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredProcedureSummary;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredProcedureTarget;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredResultPredicate;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredResultUseObligation;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredReturnedCallable;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredSemanticModelPack;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredSummaryEffect;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredSummaryExitKind;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredSummaryInput;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredSummaryLocation;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredSummaryLocationKind;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredSummaryOutput;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredSummaryPort;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredSummaryTransfer;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::CALLABLE_SURFACE_MIN_SCHEMA_VERSION;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::CALLABLE_VALUES_MIN_SCHEMA_VERSION;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::CHANNEL_CLOSE_EFFECTS_MIN_SCHEMA_VERSION;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesCoverage;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesFact;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesFamily;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesPayload;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::CompiledClassDecoratorIdentity;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::CompiledClassDecoratorKeyword;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::CompiledNormalReturnTypeRefinement;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::CompiledOperationPrecondition;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::CompiledPayload;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::CompiledResultPredicate;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::CompiledShardDescriptor;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::CompiledSummaryEffect;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::CompiledSummaryInput;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::Completeness;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::DecodeLimits;

    use brokk_bifrost_analysis::analyzer::semantic_model::validate::Diagnostic;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::EXACT_RETURN_CLASSES_MIN_SCHEMA_VERSION;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::MAX_NORMAL_RETURN_TYPE_REFINEMENT_RECEIVER_MEMBERS;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::MemberKind;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::NO_CONCURRENCY_EFFECTS_MIN_SCHEMA_VERSION;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::PROCEDURE_TARGET_INVENTORY_PREFIX;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::ParameterRole;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::PayloadKind;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::RESULT_USE_OBLIGATIONS_MIN_SCHEMA_VERSION;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::ResultUseObligationKind;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::SEMANTIC_MODEL_SCHEMA_VERSION;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::TYPED_VALUES_AND_PARAMETER_ROLES_MIN_SCHEMA_VERSION;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::TypeRef;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::UNKNOWN_TYPE_MIN_SCHEMA_VERSION;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::WireCompiledShard;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::authored_procedure_summary_from_compiled;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::canonical_json;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::compiled_from_wire;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::content_digest;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::decode_manifest;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::decode_shard;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::decode_shard_for_manifest;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::manifest_content_digest;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::payload_inventory;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::read_shard_wire;

    use brokk_bifrost_analysis::analyzer::semantic_model::artifact::semantic_digest;

    use brokk_bifrost_analysis::analyzer::semantic_model::compiler::CompilerOptions;

    use brokk_bifrost_analysis::analyzer::semantic_model::compiler::CompressionPolicy;

    use brokk_bifrost_analysis::analyzer::semantic_model::source::SourceFormat;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::VERSION_INDEPENDENT_COMPATIBILITY_SCHEMA_VERSION;

    use brokk_bifrost_analysis::analyzer::semantic_model::compiler::compile_pack;

    use brokk_bifrost_analysis::analyzer::semantic_model::compiler::compile_source;
    use brokk_bifrost_test_macros::hardwon;
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use std::io::Write;

    const DECLARATIONS: &[u8] =
        include_bytes!("../../../testdata/semantic-model-packs/declarations-v1.json");
    const PROCEDURE_SUMMARIES: &[u8] =
        include_bytes!("../../../testdata/semantic-model-packs/procedure-summaries-v1.json");

    #[test]
    fn structured_procedure_formals_require_schema_eleven_and_round_trip() {
        let mut source: serde_json::Value = serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        source["schema_version"] = 11.into();
        source["compatibility"]
            .as_object_mut()
            .unwrap()
            .remove("bifrost");
        source["shards"][0]["payload"]["summaries"][0]["target"]["formals"] =
            serde_json::json!([{"name": "value", "optional": true}]);
        let compiled = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .expect("schema eleven accepts structured procedure formals");
        let shard = decode_shard(
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("structured procedure formals decode");
        let summaries = shard.payload().procedure_summaries().unwrap();
        assert_eq!(summaries[0].target.formals.len(), 1);
        assert_eq!(summaries[0].target.formals[0].name, "value");
        assert!(summaries[0].target.formals[0].optional);

        source["schema_version"] = 10.into();
        let diagnostics = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .expect_err("schema ten cannot carry structured formals");
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.code == "summary.formals_schema_version" })
        );
    }

    #[test]
    fn schema_eight_compiles_without_engine_gate_and_keeps_partial_state() {
        let mut authored: AuthoredSemanticModelPack = serde_json::from_slice(DECLARATIONS).unwrap();
        let legacy = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        assert_eq!(legacy.manifest.schema_version, 2);
        assert!(legacy.manifest.compatibility.bifrost.is_some());
        decode_manifest(&legacy.manifest_bytes, &DecodeLimits::default()).unwrap();

        authored.schema_version = VERSION_INDEPENDENT_COMPATIBILITY_SCHEMA_VERSION;
        authored.compatibility.bifrost = None;
        authored.completeness = Completeness::Partial;
        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let manifest_json: serde_json::Value =
            serde_json::from_slice(&compiled.manifest_bytes).unwrap();
        assert_eq!(
            manifest_json["schema_version"],
            VERSION_INDEPENDENT_COMPATIBILITY_SCHEMA_VERSION
        );
        assert!(manifest_json["compatibility"].get("bifrost").is_none());
        assert!(manifest_json["compatibility"].get("toolchains").is_some());
        let decoded = decode_manifest(&compiled.manifest_bytes, &DecodeLimits::default()).unwrap();
        assert_eq!(decoded.compatibility.bifrost, None);
        assert_eq!(decoded.completeness, Completeness::Partial);

        let mut forbidden_gate = manifest_json.clone();
        forbidden_gate["compatibility"]["bifrost"] = serde_json::json!("*");
        let forbidden_gate_bytes = canonical_json(&forbidden_gate).unwrap();
        assert!(matches!(
            decode_manifest(&forbidden_gate_bytes, &DecodeLimits::default()),
            Err(ArtifactError::InvalidDescriptor(message)) if message == "schema 8 and later forbid compatibility.bifrost"
        ));

        let mut null_gate = manifest_json.clone();
        null_gate["compatibility"]["bifrost"] = serde_json::Value::Null;
        let null_gate_bytes = canonical_json(&null_gate).unwrap();
        assert!(matches!(
            decode_manifest(&null_gate_bytes, &DecodeLimits::default()),
            Err(ArtifactError::InvalidJson(_))
        ));

        let mut missing_legacy_gate: serde_json::Value =
            serde_json::from_slice(&legacy.manifest_bytes).unwrap();
        missing_legacy_gate["compatibility"]
            .as_object_mut()
            .unwrap()
            .remove("bifrost");
        let missing_legacy_bytes = canonical_json(&missing_legacy_gate).unwrap();
        assert!(matches!(
            decode_manifest(&missing_legacy_bytes, &DecodeLimits::default()),
            Err(ArtifactError::InvalidDescriptor(message)) if message.contains("requires")
        ));

        let unsupported_schema_version = SEMANTIC_MODEL_SCHEMA_VERSION + 1;
        let mut unknown_schema = manifest_json.clone();
        unknown_schema["schema_version"] = serde_json::json!(unsupported_schema_version);
        let unknown_schema_bytes = canonical_json(&unknown_schema).unwrap();
        assert_eq!(
            decode_manifest(&unknown_schema_bytes, &DecodeLimits::default()),
            Err(ArtifactError::UnsupportedVersion(
                unsupported_schema_version
            ))
        );

        let mut missing_legacy = authored.clone();
        missing_legacy.schema_version = 7;
        assert!(
            compile_pack(&missing_legacy, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code == "compatibility.schema_shape")
        );

        let mut mixed_schema_eight = authored.clone();
        mixed_schema_eight.compatibility.bifrost = Some("=0.12.0".to_owned());
        assert!(
            compile_pack(&mixed_schema_eight, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code == "compatibility.schema_shape")
        );

        let mut unknown_schema = authored;
        unknown_schema.schema_version = unsupported_schema_version;
        assert!(
            compile_pack(&unknown_schema, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code == "schema.unsupported_version")
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#3815: schema-aware native-pack compatibility disagreed across authoring and compilation"
    )]
    #[test]
    fn authoring_schema_and_rust_compiler_agree_on_engine_gate_shapes() {
        let schema: serde_json::Value = serde_json::from_str(
            &brokk_bifrost_analysis::analyzer::semantic_model::authoring_json_schema(),
        )
        .unwrap();
        let validator = jsonschema::draft202012::new(&schema)
            .expect("semantic-model authoring schema is valid Draft 2020-12");
        let fixture: serde_json::Value = serde_json::from_slice(DECLARATIONS).unwrap();

        let assert_agreement = |value: &serde_json::Value, accepted: bool| {
            assert_eq!(validator.is_valid(value), accepted);
            let bytes = serde_json::to_vec(value).unwrap();
            assert_eq!(
                compile_source(SourceFormat::Json, &bytes, &CompilerOptions::default()).is_ok(),
                accepted
            );
        };

        assert_agreement(&fixture, true);

        let mut missing_legacy_gate = fixture.clone();
        missing_legacy_gate["compatibility"]
            .as_object_mut()
            .unwrap()
            .remove("bifrost");
        assert_agreement(&missing_legacy_gate, false);

        let mut native = fixture;
        native["schema_version"] = serde_json::json!(SEMANTIC_MODEL_SCHEMA_VERSION);
        native["compatibility"]
            .as_object_mut()
            .unwrap()
            .remove("bifrost");
        native["compatibility"]
            .as_object_mut()
            .unwrap()
            .remove("toolchains");
        assert_agreement(&native, true);
        let decoded: AuthoredSemanticModelPack = serde_json::from_value(native.clone()).unwrap();
        assert!(decoded.compatibility.bifrost.is_none());
        assert!(decoded.compatibility.toolchains.is_empty());

        let mut native_with_gate = native.clone();
        native_with_gate["compatibility"]["bifrost"] = serde_json::json!("=0.12.0");
        assert_agreement(&native_with_gate, false);

        let mut native_with_null_gate = native;
        native_with_null_gate["compatibility"]["bifrost"] = serde_json::Value::Null;
        assert_agreement(&native_with_null_gate, false);
    }

    #[test]
    fn callable_inventory_round_trips_only_in_its_schema() {
        let mut authored: AuthoredSemanticModelPack = serde_json::from_slice(DECLARATIONS).unwrap();
        authored.schema_version = CALLABLE_SURFACE_MIN_SCHEMA_VERSION;
        let AuthoredPayload::DeclarationFacts { types, .. } = &mut authored.shards[0].payload
        else {
            unreachable!()
        };
        types[0].callable_surface_complete = true;
        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        assert!(decoded.payload().declaration_facts().unwrap().0[0].callable_surface_complete);
        authored.schema_version = CALLABLE_SURFACE_MIN_SCHEMA_VERSION - 1;
        assert!(
            compile_pack(&authored, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code == "schema.callable_surface_version")
        );
    }

    fn callable_values_authored_pack() -> AuthoredSemanticModelPack {
        let mut authored: AuthoredSemanticModelPack = serde_json::from_slice(DECLARATIONS).unwrap();
        authored.schema_version = CALLABLE_VALUES_MIN_SCHEMA_VERSION;
        authored.compatibility.bifrost = None;
        authored.language = "go".to_owned();
        let digest = "b".repeat(64);
        for selector in &mut authored.shards[0].activation {
            selector.artifact_sha256 = Some(digest.clone());
        }
        let literal_id = "go.literal.callback".to_owned();
        authored.shards[0].callable_values = Some(CallableValuesPayload {
            facts: vec![CallableValuesFact {
                payload: brokk_bifrost_analysis::analyzer::semantic_model::csmi::CsmiCallableValuesPayload::ReturnedCallable {
                    callable: "member.widget.create".to_owned(),
                    result: 0,
                    target: literal_id.clone(),
                },
                provenance: vec!["opaque.producer.fact".to_owned()],
            }],
            coverage: vec![CallableValuesCoverage {
                family: CallableValuesFamily::ReturnedCallables,
                callable: "member.widget.create".to_owned(),
                status: brokk_bifrost_analysis::analyzer::semantic_model::csmi::CsmiCoverageStatus::Partial,
                limitations: Vec::new(),
                provenance: vec!["opaque.producer.coverage".to_owned()],
            }],
            anonymous_callables: vec![AnonymousCallableIdentity {
                id: literal_id,
                artifact_sha256: digest,
                package_identity: "example.test/module/pkg".to_owned(),
                anchor: brokk_bifrost_analysis::analyzer::semantic_model::model::SourceAnchor {
                    file: "callbacks.go".to_owned(),
                    byte_range: brokk_bifrost_analysis::analyzer::semantic_model::model::SourceByteRange { start: 20, end: 50 },
                    kind: brokk_bifrost_analysis::analyzer::semantic_model::SourceDeclarationKind::FunctionLiteral,
                },
                lexical_owner_chain: vec![brokk_bifrost_analysis::analyzer::semantic_model::model::SourceAnchor {
                    file: "callbacks.go".to_owned(),
                    byte_range: brokk_bifrost_analysis::analyzer::semantic_model::model::SourceByteRange { start: 0, end: 100 },
                    kind: brokk_bifrost_analysis::analyzer::semantic_model::SourceDeclarationKind::Function,
                }],
                signature: brokk_bifrost_analysis::analyzer::semantic_model::model::SourceCallableShape {
                    function_type: brokk_bifrost_analysis::analyzer::semantic_model::model::SourceTypeNode {
                        file: "callbacks.go".to_owned(),
                        byte_range: brokk_bifrost_analysis::analyzer::semantic_model::model::SourceByteRange { start: 20, end: 35 },
                    },
                    parameters: Vec::new(),
                    results: Vec::new(),
                    declaration_chain: Vec::new(),
                },
            }],
        });
        authored
    }

    #[test]
    fn callable_values_encode_decode_hash_and_preserve_old_wire_shape() {
        let authored = callable_values_authored_pack();
        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        assert_eq!(
            compiled.manifest.schema_version,
            CALLABLE_VALUES_MIN_SCHEMA_VERSION
        );

        use brokk_bifrost_analysis::analyzer::semantic_model::csmi::export::CsmiArtifactEvidence;

        use brokk_bifrost_analysis::analyzer::semantic_model::csmi::export::CsmiExportError;

        use brokk_bifrost_analysis::analyzer::semantic_model::csmi::export::CsmiExportOptions;

        use brokk_bifrost_analysis::analyzer::semantic_model::csmi::export::export_csmi_pack;

        use brokk_bifrost_analysis::analyzer::semantic_model::csmi::export::export_runtime_contracts_csmi_pack;
        let options = CsmiExportOptions::default();
        let artifact = CsmiArtifactEvidence::new("pkg:generic/test@1.0.0", "a".repeat(64));
        // This generic selector is insufficient for the artifact-local Go
        // source mapping. Standard export now supports properly pinned Go
        // callable-values; runtime-contract export still refuses the carrier.
        assert!(matches!(
            export_csmi_pack(&compiled, &artifact, &options).unwrap_err(),
            CsmiExportError::InvalidEvidence(message)
                if message.contains("exact versioned pkg:golang PURL")
        ));
        assert!(matches!(
            export_runtime_contracts_csmi_pack(&compiled, &options).unwrap_err(),
            CsmiExportError::Unsupported { path, .. } if path.ends_with(".callable_values")
        ));
        let (wire, _) = read_shard_wire(
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        assert!(wire.callable_values.is_some());

        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let callable_values = decoded.callable_values().expect("carrier round-trips");
        assert_eq!(callable_values.record_count(), 3);
        assert_eq!(callable_values.anonymous_callables.len(), 1);
        assert_eq!(
            callable_values.anonymous_callables[0].id,
            "go.literal.callback"
        );
        assert!(
            compiled.shards[0]
                .descriptor
                .defined_ids
                .iter()
                .any(|id| id == "go.literal.callback")
        );
        assert!(
            compiled.shards[0]
                .descriptor
                .referenced_ids
                .iter()
                .any(|id| id == "go.literal.callback")
        );
        assert_eq!(
            decoded.record_count(),
            compiled.shards[0].descriptor.record_count as usize
        );

        let mut changed = authored.clone();
        changed.shards[0].callable_values.as_mut().unwrap().facts[0]
            .provenance
            .push("opaque.producer.changed".to_owned());
        let changed_compiled = compile_pack(&changed, &CompilerOptions::default()).unwrap();
        assert_ne!(
            compiled.shards[0].descriptor.semantic_sha256,
            changed_compiled.shards[0].descriptor.semantic_sha256
        );

        let legacy: AuthoredSemanticModelPack = serde_json::from_slice(DECLARATIONS).unwrap();
        let legacy_compiled = compile_pack(&legacy, &CompilerOptions::default()).unwrap();
        let (legacy_wire, _) = read_shard_wire(
            &legacy_compiled.shards[0].descriptor,
            &legacy_compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        assert!(legacy_wire.callable_values.is_none());
    }

    #[test]
    fn callable_values_schema_floor_and_bad_references_fail_closed() {
        let mut old_schema = callable_values_authored_pack();
        old_schema.schema_version = CALLABLE_VALUES_MIN_SCHEMA_VERSION - 1;
        let diagnostics = compile_pack(&old_schema, &CompilerOptions::default()).unwrap_err();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "schema.callable_values_version")
        );

        let mut bad_reference = callable_values_authored_pack();
        let Some(CallableValuesPayload { facts, .. }) =
            bad_reference.shards[0].callable_values.as_mut()
        else {
            unreachable!();
        };
        let brokk_bifrost_analysis::analyzer::semantic_model::csmi::CsmiCallableValuesPayload::ReturnedCallable {
            target,
            ..
        } = &mut facts[0].payload
        else {
            unreachable!();
        };
        *target = "missing.callable".to_owned();
        let diagnostics = compile_pack(&bad_reference, &CompilerOptions::default()).unwrap_err();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "callable_values.symbol_reference")
        );
    }

    #[test]
    fn anonymous_callable_targets_require_exact_artifact_owner_range_and_unique_id() {
        let mut wrong_artifact = callable_values_authored_pack();
        wrong_artifact.shards[0]
            .callable_values
            .as_mut()
            .unwrap()
            .anonymous_callables[0]
            .artifact_sha256 = "c".repeat(64);
        let diagnostics = compile_pack(&wrong_artifact, &CompilerOptions::default()).unwrap_err();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "callable_values.anonymous_artifact")
        );

        let mut wrong_owner = callable_values_authored_pack();
        wrong_owner.shards[0]
            .callable_values
            .as_mut()
            .unwrap()
            .anonymous_callables[0]
            .lexical_owner_chain[0]
            .byte_range
            .start = 25;
        let diagnostics = compile_pack(&wrong_owner, &CompilerOptions::default()).unwrap_err();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "callable_values.anonymous_owner")
        );

        let mut wrong_range = callable_values_authored_pack();
        wrong_range.shards[0]
            .callable_values
            .as_mut()
            .unwrap()
            .anonymous_callables[0]
            .signature
            .function_type
            .byte_range
            .start = 21;
        let diagnostics = compile_pack(&wrong_range, &CompilerOptions::default()).unwrap_err();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "callable_values.anonymous_signature")
        );

        let mut duplicate = callable_values_authored_pack();
        let identity = duplicate.shards[0]
            .callable_values
            .as_ref()
            .unwrap()
            .anonymous_callables[0]
            .clone();
        duplicate.shards[0]
            .callable_values
            .as_mut()
            .unwrap()
            .anonymous_callables
            .push(identity);
        let diagnostics = compile_pack(&duplicate, &CompilerOptions::default()).unwrap_err();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.code == "callable_values.anonymous_duplicate_id" })
        );
    }

    #[test]
    fn field_member_with_signature_is_not_a_callable_values_factory() {
        let mut authored = callable_values_authored_pack();
        let AuthoredPayload::DeclarationFacts { members, .. } = &mut authored.shards[0].payload
        else {
            unreachable!();
        };
        let factory = members
            .iter_mut()
            .find(|member| member.id == "member.widget.create")
            .expect("fixture factory member");
        factory.member_kind = MemberKind::Field;
        let diagnostics = compile_pack(&authored, &CompilerOptions::default()).unwrap_err();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "callable_values.factory")
        );
    }

    #[test]
    fn unknown_type_refs_compile_and_decode_in_schema_nine() {
        let mut authored: AuthoredSemanticModelPack = serde_json::from_slice(DECLARATIONS).unwrap();
        authored.schema_version = UNKNOWN_TYPE_MIN_SCHEMA_VERSION;
        authored.compatibility.bifrost = None;
        let AuthoredPayload::DeclarationFacts { members, .. } = &mut authored.shards[0].payload
        else {
            unreachable!();
        };
        let signature = members[0]
            .signature
            .as_mut()
            .expect("fixture member has a signature");
        let original_parameter_count = signature.parameters.len();
        let original_parameter_name = signature.parameters[0].name.clone();
        let original_parameter_optional = signature.parameters[0].optional;
        let original_parameter_variadic = signature.parameters[0].variadic;
        let original_passing_mode = signature.parameters[0].passing_mode;
        signature.parameters[0].r#type = TypeRef::Named {
            name: "typing.Optional".to_owned(),
            arguments: vec![TypeRef::Unknown],
            nullable: false,
        };
        signature.returns = Some(TypeRef::Unknown);

        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let (_, members, _) = decoded.payload().declaration_facts().unwrap();
        let signature = members[0]
            .signature
            .as_ref()
            .expect("decoded fixture member has a signature");
        assert!(signature.contains_unknown_types());
        assert_eq!(signature.parameters.len(), original_parameter_count);
        assert_eq!(signature.parameters[0].name, original_parameter_name);
        assert_eq!(
            signature.parameters[0].optional,
            original_parameter_optional
        );
        assert_eq!(
            signature.parameters[0].variadic,
            original_parameter_variadic
        );
        assert_eq!(signature.parameters[0].passing_mode, original_passing_mode);
        assert_eq!(
            signature.parameters[0].r#type,
            TypeRef::Named {
                name: "typing.Optional".to_owned(),
                arguments: vec![TypeRef::Unknown],
                nullable: false,
            }
        );
        assert_eq!(signature.returns, Some(TypeRef::Unknown));

        authored.schema_version = UNKNOWN_TYPE_MIN_SCHEMA_VERSION - 1;
        assert!(
            compile_pack(&authored, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| {
                    diagnostic.code == "schema.unknown_type_version"
                        && diagnostic.path.ends_with("signature.returns")
                })
        );
    }

    #[test]
    fn callable_parameter_roles_require_schema_fifteen_and_round_trip() {
        let mut authored: AuthoredSemanticModelPack = serde_json::from_slice(DECLARATIONS).unwrap();
        authored.schema_version = TYPED_VALUES_AND_PARAMETER_ROLES_MIN_SCHEMA_VERSION;
        authored.compatibility.bifrost = None;
        let AuthoredPayload::DeclarationFacts { members, .. } = &mut authored.shards[0].payload
        else {
            unreachable!();
        };
        members[0]
            .signature
            .as_mut()
            .expect("fixture member has a signature")
            .parameters[0]
            .role = Some(ParameterRole::Request);

        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let (_, members, _) = decoded.payload().declaration_facts().unwrap();
        assert_eq!(
            members[0].signature.as_ref().unwrap().parameters[0].role,
            Some(ParameterRole::Request)
        );

        authored.schema_version -= 1;
        assert!(
            compile_pack(&authored, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code == "parameter.role_schema_version")
        );
    }

    #[test]
    fn exact_return_class_sets_require_schema_sixteen() {
        let mut authored: AuthoredSemanticModelPack = serde_json::from_slice(DECLARATIONS).unwrap();
        authored.schema_version = EXACT_RETURN_CLASSES_MIN_SCHEMA_VERSION;
        authored.compatibility.bifrost = None;
        let AuthoredPayload::DeclarationFacts { members, .. } = &mut authored.shards[0].payload
        else {
            unreachable!();
        };
        members[0].exact_return_classes = members[0]
            .signature
            .as_ref()
            .and_then(|signature| signature.returns.clone())
            .into_iter()
            .collect();

        compile_pack(&authored, &CompilerOptions::default()).unwrap();

        authored.schema_version = EXACT_RETURN_CLASSES_MIN_SCHEMA_VERSION - 1;
        assert!(
            compile_pack(&authored, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| {
                    diagnostic.code == "declaration.exact_return_classes_schema_version"
                        && diagnostic.path.ends_with("exact_return_classes")
                })
        );
    }

    #[test]
    fn reviewed_result_use_obligation_round_trips_and_rejects_unsupported_claims() {
        let mut authored: AuthoredSemanticModelPack =
            serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        authored.schema_version = RESULT_USE_OBLIGATIONS_MIN_SCHEMA_VERSION;
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
        else {
            unreachable!()
        };
        let summary = &mut summaries[1];
        summary.effects.clear();
        summary.ordinary_heap_unchanged = true;
        summary.normal_result_count = Some(1);
        summary.result_use_obligations = vec![AuthoredResultUseObligation {
            result_ordinal: 0,
            kind: ResultUseObligationKind::PureTransformationValue,
            failure_predicate: None,
        }];
        let expected = summary.clone();

        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let observed = &decoded.payload().procedure_summaries().unwrap()[1];
        assert_eq!(observed.result_use_obligations.len(), 1);
        assert_eq!(authored_procedure_summary_from_compiled(observed), expected);

        let mut rejected = authored.clone();
        rejected.schema_version = RESULT_USE_OBLIGATIONS_MIN_SCHEMA_VERSION - 1;
        assert!(
            compile_pack(&rejected, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code == "summary.result_use_obligations_schema")
        );
        rejected.schema_version = RESULT_USE_OBLIGATIONS_MIN_SCHEMA_VERSION;
        if let AuthoredPayload::ProcedureSummaries { summaries } = &mut rejected.shards[0].payload {
            summaries[1].result_use_obligations[0].result_ordinal = 1;
        } else {
            unreachable!()
        }
        assert!(
            compile_pack(&rejected, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code == "summary.result_ordinal_out_of_range")
        );
        if let AuthoredPayload::ProcedureSummaries { summaries } = &mut rejected.shards[0].payload {
            summaries[1].result_use_obligations[0].result_ordinal = 0;
            summaries[1].ordinary_heap_unchanged = false;
        } else {
            unreachable!()
        }
        assert!(
            compile_pack(&rejected, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code
                    == "summary.pure_result_has_unreviewed_heap_effects")
        );

        let mut status = authored.clone();
        if let AuthoredPayload::ProcedureSummaries { summaries } = &mut status.shards[0].payload {
            summaries[1].ordinary_heap_unchanged = false;
            summaries[1].result_use_obligations[0] = AuthoredResultUseObligation {
                result_ordinal: 0,
                kind: ResultUseObligationKind::FallibleStatus,
                failure_predicate: Some(AuthoredResultPredicate::False),
            };
            summaries[1].completeness = Completeness::Partial;
            summaries[1].transfers.clear();
        } else {
            unreachable!()
        }
        assert!(compile_pack(&status, &CompilerOptions::default()).is_ok());
        if let AuthoredPayload::ProcedureSummaries { summaries } = &mut status.shards[0].payload {
            summaries[1].result_use_obligations[0].failure_predicate = None;
        } else {
            unreachable!()
        }
        assert!(
            compile_pack(&status, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code
                    == "summary.fallible_status_needs_failure_predicate")
        );
    }

    #[test]
    fn control_only_normal_continuation_absence_round_trips() {
        let mut authored: AuthoredSemanticModelPack =
            serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
        else {
            unreachable!()
        };
        let authored_summary = &mut summaries[1];
        authored_summary.completeness = Completeness::Partial;
        authored_summary.normal_continuation_absent = true;
        authored_summary.transfers.clear();
        authored_summary.effects.clear();
        let expected = authored_summary.clone();

        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let summary = &decoded.payload().procedure_summaries().unwrap()[1];
        assert!(summary.normal_continuation_absent);
        assert_eq!(
            authored_procedure_summary_from_compiled(summary),
            expected,
            "compiled-to-authored defensive reconstruction preserves the claim"
        );
        assert!(
            String::from_utf8(canonical_json(summary).unwrap())
                .unwrap()
                .contains("\"normal_continuation_absent\":true")
        );
    }

    #[test]
    fn normal_return_type_refinements_compile_decode_and_validate() {
        let mut authored: AuthoredSemanticModelPack =
            serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
        else {
            unreachable!()
        };
        let authored_summary = &mut summaries[1];
        authored_summary.target.parameter_count = 3;
        authored_summary.target.has_receiver = true;
        authored_summary.transfers.clear();
        authored_summary.effects.clear();
        authored_summary.locations.clear();
        authored_summary.completeness = Completeness::Partial;
        authored_summary.normal_return_type_refinements = vec![
            AuthoredNormalReturnTypeRefinement {
                parameter_ordinal: 1,
                class_parameter_ordinal: 2,
                required_receiver_members: vec!["helper".to_owned(), "fail".to_owned()],
            },
            AuthoredNormalReturnTypeRefinement {
                parameter_ordinal: 0,
                class_parameter_ordinal: 1,
                required_receiver_members: Vec::new(),
            },
        ];
        let mut expected = authored_summary.clone();
        expected.normal_return_type_refinements[0]
            .required_receiver_members
            .sort();
        expected.normal_return_type_refinements.sort();

        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let summary = decoded
            .payload()
            .procedure_summaries()
            .unwrap()
            .iter()
            .find(|summary| summary.id == expected.id)
            .unwrap();
        assert_eq!(
            summary.normal_return_type_refinements,
            vec![
                CompiledNormalReturnTypeRefinement {
                    parameter_ordinal: 0,
                    class_parameter_ordinal: 1,
                    required_receiver_members: Vec::new(),
                },
                CompiledNormalReturnTypeRefinement {
                    parameter_ordinal: 1,
                    class_parameter_ordinal: 2,
                    required_receiver_members: vec!["fail".to_owned(), "helper".to_owned()],
                },
            ]
        );
        assert_eq!(authored_procedure_summary_from_compiled(summary), expected);
        assert!(
            String::from_utf8(canonical_json(summary).unwrap())
                .unwrap()
                .contains("\"normal_return_type_refinements\"")
        );

        let empty: AuthoredSemanticModelPack = serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        let empty_summary = match &empty.shards[0].payload {
            AuthoredPayload::ProcedureSummaries { summaries } => &summaries[1],
            _ => unreachable!(),
        };
        assert!(
            !String::from_utf8(canonical_json(empty_summary).unwrap())
                .unwrap()
                .contains("normal_return_type_refinements")
        );

        fn diagnostics_for(
            refinements: Vec<AuthoredNormalReturnTypeRefinement>,
            parameter_count: u32,
            variadic: bool,
            has_receiver: bool,
        ) -> Vec<Diagnostic> {
            let mut authored: AuthoredSemanticModelPack =
                serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
            let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
            else {
                unreachable!()
            };
            let summary = &mut summaries[1];
            summary.target.parameter_count = parameter_count;
            summary.target.variadic = variadic;
            summary.target.has_receiver = has_receiver;
            summary.normal_return_type_refinements = refinements;
            compile_pack(&authored, &CompilerOptions::default()).unwrap_err()
        }

        assert!(
            diagnostics_for(
                vec![AuthoredNormalReturnTypeRefinement {
                    parameter_ordinal: 1,
                    class_parameter_ordinal: 0,
                    required_receiver_members: Vec::new(),
                }],
                1,
                false,
                false,
            )
            .iter()
            .any(|diagnostic| diagnostic.code == "summary.parameter_ordinal_out_of_range")
        );
        assert!(
            diagnostics_for(
                vec![AuthoredNormalReturnTypeRefinement {
                    parameter_ordinal: 0,
                    class_parameter_ordinal: 0,
                    required_receiver_members: Vec::new(),
                }],
                1,
                false,
                false,
            )
            .iter()
            .any(|diagnostic| {
                diagnostic.code == "summary.same_normal_return_type_refinement_parameter"
            })
        );
        assert!(
            diagnostics_for(
                vec![
                    AuthoredNormalReturnTypeRefinement {
                        parameter_ordinal: 0,
                        class_parameter_ordinal: 1,
                        required_receiver_members: Vec::new(),
                    },
                    AuthoredNormalReturnTypeRefinement {
                        parameter_ordinal: 0,
                        class_parameter_ordinal: 1,
                        required_receiver_members: Vec::new(),
                    },
                ],
                2,
                false,
                false,
            )
            .iter()
            .any(|diagnostic| {
                diagnostic.code == "summary.duplicate_normal_return_type_refinement"
            })
        );
        assert!(
            diagnostics_for(
                vec![
                    AuthoredNormalReturnTypeRefinement {
                        parameter_ordinal: 0,
                        class_parameter_ordinal: 1,
                        required_receiver_members: Vec::new(),
                    },
                    AuthoredNormalReturnTypeRefinement {
                        parameter_ordinal: 0,
                        class_parameter_ordinal: 2,
                        required_receiver_members: Vec::new(),
                    },
                ],
                3,
                false,
                false,
            )
            .iter()
            .any(|diagnostic| {
                diagnostic.code == "summary.conflicting_normal_return_type_refinement"
            })
        );
        assert!(
            diagnostics_for(
                vec![AuthoredNormalReturnTypeRefinement {
                    parameter_ordinal: 0,
                    class_parameter_ordinal: 1,
                    required_receiver_members: Vec::new(),
                }],
                2,
                true,
                false,
            )
            .iter()
            .any(|diagnostic| diagnostic.code == "summary.unsupported_variadic_tail_reference")
        );
        assert!(
            diagnostics_for(
                vec![AuthoredNormalReturnTypeRefinement {
                    parameter_ordinal: 0,
                    class_parameter_ordinal: 1,
                    required_receiver_members: vec!["fail".to_owned()],
                }],
                2,
                false,
                false,
            )
            .iter()
            .any(|diagnostic| {
                diagnostic.code == "summary.required_receiver_members_without_receiver"
            })
        );
        assert!(
            diagnostics_for(
                vec![AuthoredNormalReturnTypeRefinement {
                    parameter_ordinal: 0,
                    class_parameter_ordinal: 1,
                    required_receiver_members: vec!["fail".to_owned(), "fail".to_owned()],
                }],
                2,
                false,
                true,
            )
            .iter()
            .any(|diagnostic| { diagnostic.code == "summary.duplicate_required_receiver_member" })
        );
        assert!(
            diagnostics_for(
                vec![AuthoredNormalReturnTypeRefinement {
                    parameter_ordinal: 0,
                    class_parameter_ordinal: 1,
                    required_receiver_members: vec![String::new()],
                }],
                2,
                false,
                true,
            )
            .iter()
            .any(|diagnostic| diagnostic.code == "text.empty")
        );
        let bounded_members = (0..=MAX_NORMAL_RETURN_TYPE_REFINEMENT_RECEIVER_MEMBERS)
            .map(|index| format!("member{index}"))
            .collect();
        assert!(
            diagnostics_for(
                vec![AuthoredNormalReturnTypeRefinement {
                    parameter_ordinal: 0,
                    class_parameter_ordinal: 1,
                    required_receiver_members: bounded_members,
                }],
                2,
                false,
                true,
            )
            .iter()
            .any(|diagnostic| {
                diagnostic.code == "limit.normal_return_type_refinement_receiver_members"
            })
        );
    }

    #[test]
    fn class_decorator_identity_compile_decode_and_canonicalize() {
        let mut authored: AuthoredSemanticModelPack =
            serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
        else {
            unreachable!()
        };
        let summary = &mut summaries[1];
        summary.class_decorator_identity = Some(AuthoredClassDecoratorIdentity {
            direct: false,
            factory_keywords: Some(vec![
                AuthoredClassDecoratorKeyword {
                    name: "slots".to_owned(),
                    allowed_values: vec![true, false],
                },
                AuthoredClassDecoratorKeyword {
                    name: "frozen".to_owned(),
                    allowed_values: vec![false],
                },
            ]),
        });
        let mut expected = summary.clone();
        let identity = expected.class_decorator_identity.as_mut().unwrap();
        let keywords = identity.factory_keywords.as_mut().unwrap();
        for keyword in keywords.iter_mut() {
            keyword.allowed_values.sort_unstable();
        }
        keywords.sort();

        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let compiled_summary = decoded
            .payload()
            .procedure_summaries()
            .unwrap()
            .iter()
            .find(|candidate| candidate.id == expected.id)
            .unwrap();
        assert_eq!(
            compiled_summary.class_decorator_identity,
            Some(CompiledClassDecoratorIdentity {
                direct: false,
                factory_keywords: Some(vec![
                    CompiledClassDecoratorKeyword {
                        name: "frozen".to_owned(),
                        allowed_values: vec![false],
                    },
                    CompiledClassDecoratorKeyword {
                        name: "slots".to_owned(),
                        allowed_values: vec![false, true],
                    },
                ]),
            })
        );
        let round_tripped = authored_procedure_summary_from_compiled(compiled_summary);
        assert_eq!(
            round_tripped.class_decorator_identity, expected.class_decorator_identity,
            "the decorator identity claim survives authored/compiled round-trip"
        );
        assert!(
            String::from_utf8(canonical_json(compiled_summary).unwrap())
                .unwrap()
                .contains("\"class_decorator_identity\"")
        );

        let omitted: AuthoredSemanticModelPack =
            serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        let omitted_summary = match &omitted.shards[0].payload {
            AuthoredPayload::ProcedureSummaries { summaries } => &summaries[1],
            _ => unreachable!(),
        };
        assert!(
            !String::from_utf8(canonical_json(omitted_summary).unwrap())
                .unwrap()
                .contains("class_decorator_identity")
        );
    }

    #[test]
    fn class_decorator_identity_validation_rejects_unsafe_claims() {
        fn diagnostics_for(
            target: AuthoredProcedureTarget,
            completeness: Completeness,
            identity: AuthoredClassDecoratorIdentity,
            normal_continuation_absent: bool,
        ) -> Vec<Diagnostic> {
            diagnostics_for_with_covers(
                target,
                completeness,
                identity,
                normal_continuation_absent,
                false,
            )
        }

        fn diagnostics_for_with_covers(
            target: AuthoredProcedureTarget,
            completeness: Completeness,
            identity: AuthoredClassDecoratorIdentity,
            normal_continuation_absent: bool,
            covers_overrides: bool,
        ) -> Vec<Diagnostic> {
            let mut authored: AuthoredSemanticModelPack =
                serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
            let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
            else {
                unreachable!()
            };
            summaries[1].target = target;
            summaries[1].completeness = completeness;
            summaries[1].covers_overrides = covers_overrides;
            summaries[1].normal_continuation_absent = normal_continuation_absent;
            summaries[1].class_decorator_identity = Some(identity);
            compile_pack(&authored, &CompilerOptions::default()).unwrap_err()
        }

        fn compiles_variadic_direct(parameter_count: u32) -> bool {
            let mut authored: AuthoredSemanticModelPack =
                serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
            let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
            else {
                unreachable!()
            };
            let summary = &mut summaries[1];
            summary.target.parameter_count = parameter_count;
            summary.target.variadic = true;
            summary.transfers.clear();
            summary.effects.clear();
            summary.locations.clear();
            summary.class_decorator_identity = Some(AuthoredClassDecoratorIdentity {
                direct: true,
                factory_keywords: None,
            });
            compile_pack(&authored, &CompilerOptions::default()).is_ok()
        }

        let target = AuthoredProcedureTarget {
            path: "com/acme/Flows.class".to_owned(),
            symbol: "wrapper(java.lang.String)".to_owned(),
            has_receiver: false,
            variadic: false,
            parameter_count: 1,
            formals: Vec::new(),
        };
        assert!(
            diagnostics_for(
                target.clone(),
                Completeness::Partial,
                AuthoredClassDecoratorIdentity {
                    direct: true,
                    factory_keywords: None,
                },
                false,
            )
            .iter()
            .any(|diagnostic| diagnostic.code
                == "summary.class_decorator_identity_requires_complete")
        );
        assert!(
            diagnostics_for(
                AuthoredProcedureTarget {
                    parameter_count: 0,
                    ..target.clone()
                },
                Completeness::Complete,
                AuthoredClassDecoratorIdentity {
                    direct: true,
                    factory_keywords: None,
                },
                false,
            )
            .iter()
            .any(|diagnostic| diagnostic.code == "summary.class_decorator_identity_arity")
        );
        assert!(
            diagnostics_for(
                AuthoredProcedureTarget {
                    parameter_count: 2,
                    ..target.clone()
                },
                Completeness::Complete,
                AuthoredClassDecoratorIdentity {
                    direct: true,
                    factory_keywords: None,
                },
                false,
            )
            .iter()
            .any(|diagnostic| diagnostic.code == "summary.class_decorator_identity_arity")
        );
        assert!(
            diagnostics_for(
                AuthoredProcedureTarget {
                    parameter_count: 3,
                    variadic: true,
                    ..target.clone()
                },
                Completeness::Complete,
                AuthoredClassDecoratorIdentity {
                    direct: true,
                    factory_keywords: None,
                },
                false,
            )
            .iter()
            .any(|diagnostic| diagnostic.code == "summary.class_decorator_identity_arity")
        );
        assert!(compiles_variadic_direct(1));
        assert!(compiles_variadic_direct(2));
        assert!(diagnostics_for(
            AuthoredProcedureTarget {
                has_receiver: true,
                ..target.clone()
            },
            Completeness::Complete,
            AuthoredClassDecoratorIdentity {
                direct: true,
                factory_keywords: None,
            },
            false,
        )
        .iter()
        .any(|diagnostic| diagnostic.code == "summary.class_decorator_identity_receiver_target"));
        assert!(
            diagnostics_for(
                target.clone(),
                Completeness::Complete,
                AuthoredClassDecoratorIdentity {
                    direct: false,
                    factory_keywords: None,
                },
                false,
            )
            .iter()
            .any(|diagnostic| diagnostic.code == "summary.empty_class_decorator_identity")
        );
        assert!(
            diagnostics_for(
                target.clone(),
                Completeness::Complete,
                AuthoredClassDecoratorIdentity {
                    direct: false,
                    factory_keywords: Some(vec![AuthoredClassDecoratorKeyword {
                        name: "frozen".to_owned(),
                        allowed_values: vec![],
                    }]),
                },
                false,
            )
            .iter()
            .any(|diagnostic| diagnostic.code
                == "summary.empty_class_decorator_factory_allowed_values")
        );
        assert!(
            diagnostics_for(
                target.clone(),
                Completeness::Complete,
                AuthoredClassDecoratorIdentity {
                    direct: true,
                    factory_keywords: None,
                },
                true,
            )
            .iter()
            .any(|diagnostic| diagnostic.code == "summary.normal_continuation_conflict")
        );
        assert!(
            diagnostics_for_with_covers(
                AuthoredProcedureTarget {
                    parameter_count: 1,
                    ..target
                },
                Completeness::Complete,
                AuthoredClassDecoratorIdentity {
                    direct: true,
                    factory_keywords: None,
                },
                false,
                true,
            )
            .iter()
            .any(|diagnostic| {
                diagnostic.code == "summary.class_decorator_identity_covers_overrides"
            })
        );
    }

    #[test]
    fn absent_procedure_preconditions_preserve_existing_bytes_and_digests() {
        let authored: AuthoredSemanticModelPack =
            serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        let AuthoredPayload::ProcedureSummaries { summaries } = &authored.shards[0].payload else {
            unreachable!()
        };
        assert!(
            summaries
                .iter()
                .all(|summary| summary.preconditions.is_none())
        );
        assert!(summaries.iter().all(|summary| {
            !String::from_utf8(canonical_json(summary).unwrap())
                .unwrap()
                .contains("\"preconditions\"")
        }));

        // Captured for schema v2 before procedure-level preconditions existed.
        // An omitted optional claim must leave the authored content, compiled
        // shard, and manifest identities byte-for-byte compatible within the
        // same schema version.
        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        brokk_bifrost_analysis::test_support::assert_no_optional_claim_pack_v2_digests(&compiled);

        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        assert!(
            decoded
                .payload()
                .procedure_summaries()
                .unwrap()
                .iter()
                .all(|summary| summary.preconditions.is_none())
        );
        assert!(
            !String::from_utf8(canonical_json(&decoded).unwrap())
                .unwrap()
                .contains("\"preconditions\"")
        );
    }

    #[test]
    fn procedure_precondition_review_states_compile_canonically_and_round_trip() {
        let mut reviewed_empty: AuthoredSemanticModelPack =
            serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        let unreviewed = reviewed_empty.clone();
        let AuthoredPayload::ProcedureSummaries { summaries } =
            &mut reviewed_empty.shards[0].payload
        else {
            unreachable!()
        };
        summaries[0].preconditions = Some(Vec::new());

        let options = CompilerOptions {
            compression: CompressionPolicy::AlwaysRaw,
            ..CompilerOptions::default()
        };
        let baseline = compile_pack(&unreviewed, &options).unwrap();
        let reviewed_empty_compiled = compile_pack(&reviewed_empty, &options)
            .expect("a reviewed-empty precondition set is a substantive summary claim");
        assert_ne!(
            reviewed_empty_compiled.manifest.semantic_sha256,
            baseline.manifest.semantic_sha256
        );
        assert!(
            String::from_utf8(reviewed_empty_compiled.shards[0].bytes.clone())
                .unwrap()
                .contains("\"preconditions\":[]")
        );

        let mut precondition_only = reviewed_empty.clone();
        let AuthoredPayload::ProcedureSummaries { summaries } =
            &mut precondition_only.shards[0].payload
        else {
            unreachable!()
        };
        summaries[0].transfers.clear();
        summaries[0].effects.clear();
        compile_pack(&precondition_only, &options)
            .expect("a reviewed-empty precondition set is a substantive summary claim");

        let decoded = decode_shard_for_manifest(
            &reviewed_empty_compiled.manifest,
            &reviewed_empty_compiled.shards[0].descriptor,
            &reviewed_empty_compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        assert_eq!(
            decoded.payload().procedure_summaries().unwrap()[0].preconditions,
            Some(Vec::new())
        );

        let mut populated = reviewed_empty;
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut populated.shards[0].payload
        else {
            unreachable!()
        };
        summaries[0].preconditions = Some(vec![
            AuthoredOperationPrecondition {
                input: AuthoredSummaryInput::Parameter { ordinal: 0 },
                predicate: AuthoredResultPredicate::Null,
            },
            AuthoredOperationPrecondition {
                input: AuthoredSummaryInput::Receiver {},
                predicate: AuthoredResultPredicate::NonNull,
            },
        ]);
        let populated_compiled = compile_pack(&populated, &options).unwrap();
        let mut reordered = populated.clone();
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut reordered.shards[0].payload
        else {
            unreachable!()
        };
        summaries[0].preconditions.as_mut().unwrap().reverse();
        assert_eq!(
            compile_pack(&reordered, &options).unwrap(),
            populated_compiled,
            "operation preconditions compile as a deterministic set keyed by input"
        );
        assert_ne!(
            populated_compiled.manifest.semantic_sha256,
            reviewed_empty_compiled.manifest.semantic_sha256
        );

        let decoded = decode_shard_for_manifest(
            &populated_compiled.manifest,
            &populated_compiled.shards[0].descriptor,
            &populated_compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let summary = &decoded.payload().procedure_summaries().unwrap()[0];
        assert_eq!(
            summary.preconditions,
            Some(vec![
                CompiledOperationPrecondition {
                    input: CompiledSummaryInput::Receiver {},
                    predicate: CompiledResultPredicate::NonNull,
                },
                CompiledOperationPrecondition {
                    input: CompiledSummaryInput::Parameter { ordinal: 0 },
                    predicate: CompiledResultPredicate::Null,
                },
            ])
        );
        assert_eq!(
            authored_procedure_summary_from_compiled(summary).preconditions,
            Some(vec![
                AuthoredOperationPrecondition {
                    input: AuthoredSummaryInput::Receiver {},
                    predicate: AuthoredResultPredicate::NonNull,
                },
                AuthoredOperationPrecondition {
                    input: AuthoredSummaryInput::Parameter { ordinal: 0 },
                    predicate: AuthoredResultPredicate::Null,
                },
            ])
        );
    }

    #[test]
    fn procedure_preconditions_validate_inputs_duplicates_and_conflicts() {
        fn with_preconditions(
            preconditions: Vec<AuthoredOperationPrecondition>,
        ) -> AuthoredSemanticModelPack {
            let mut authored: AuthoredSemanticModelPack =
                serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
            let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
            else {
                unreachable!()
            };
            summaries[1].preconditions = Some(preconditions);
            authored
        }

        let receiver = AuthoredOperationPrecondition {
            input: AuthoredSummaryInput::Receiver {},
            predicate: AuthoredResultPredicate::NonNull,
        };
        let out_of_range = AuthoredOperationPrecondition {
            input: AuthoredSummaryInput::Parameter { ordinal: u32::MAX },
            predicate: AuthoredResultPredicate::NonNull,
        };
        let parameter_null = AuthoredOperationPrecondition {
            input: AuthoredSummaryInput::Parameter { ordinal: 0 },
            predicate: AuthoredResultPredicate::Null,
        };
        let parameter_non_null = AuthoredOperationPrecondition {
            input: AuthoredSummaryInput::Parameter { ordinal: 0 },
            predicate: AuthoredResultPredicate::NonNull,
        };
        for (pack, expected_code, expected_path_suffix) in [
            (
                with_preconditions(vec![receiver]),
                "summary.receiver_unavailable",
                ".preconditions[0].input",
            ),
            (
                with_preconditions(vec![out_of_range]),
                "summary.invalid_ordinal",
                ".preconditions[0].input.ordinal",
            ),
            (
                with_preconditions(vec![parameter_null.clone(), parameter_null.clone()]),
                "summary.duplicate_operation_precondition",
                ".preconditions[1].input",
            ),
            (
                with_preconditions(vec![parameter_null, parameter_non_null]),
                "summary.conflicting_operation_precondition",
                ".preconditions[1].predicate",
            ),
        ] {
            let diagnostics = compile_pack(&pack, &CompilerOptions::default()).unwrap_err();
            assert!(
                diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == expected_code
                        && diagnostic.path.ends_with(expected_path_suffix)
                }),
                "missing `{expected_code}` at `*{expected_path_suffix}` in {diagnostics:#?}"
            );
        }

        let mut variadic = with_preconditions(vec![AuthoredOperationPrecondition {
            input: AuthoredSummaryInput::Parameter { ordinal: 0 },
            predicate: AuthoredResultPredicate::NonNull,
        }]);
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut variadic.shards[0].payload
        else {
            unreachable!()
        };
        summaries[1].target.variadic = true;
        let diagnostics = compile_pack(&variadic, &CompilerOptions::default()).unwrap_err();
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "summary.unsupported_variadic_tail_reference"
                && diagnostic.path.ends_with(".preconditions[0].input.ordinal")
        }));
    }

    #[test]
    fn concurrency_effects_validate_and_round_trip_canonically() {
        fn with_effects(effects: Vec<AuthoredConcurrencyEffect>) -> AuthoredSemanticModelPack {
            let mut authored: AuthoredSemanticModelPack =
                serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
            let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
            else {
                unreachable!()
            };
            summaries[0].concurrency_effects = effects;
            authored
        }

        let spawn = AuthoredConcurrencyEffect::TaskSpawn {
            callable: AuthoredSummaryInput::Parameter { ordinal: 0 },
            group: Some(AuthoredSummaryInput::Receiver {}),
            condition: None,
            timer: None,
        };
        let lock = AuthoredConcurrencyEffect::LockAcquire {
            lock: AuthoredSummaryInput::Receiver {},
            mode: AuthoredLockMode::Exclusive,
            condition: Some(AuthoredLockCondition::CallResultTrue),
        };
        let atomic = AuthoredConcurrencyEffect::Atomic {
            location: AuthoredSummaryInput::Parameter { ordinal: 0 },
            operation: AuthoredAtomicOperation::ReadModifyWrite,
        };
        let unsupported = AuthoredConcurrencyEffect::Unsupported {
            protocol: "sync.Cond".to_owned(),
        };
        let once = AuthoredConcurrencyEffect::OnceDo {
            once: AuthoredSummaryInput::Receiver {},
            callable: AuthoredSummaryInput::Parameter { ordinal: 0 },
        };
        let mut expected = vec![spawn.clone(), lock, atomic, unsupported, once];
        expected.sort_by_cached_key(|effect| canonical_json(effect).unwrap());
        let compiled =
            compile_pack(&with_effects(expected.clone()), &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let summary = &decoded.payload().procedure_summaries().unwrap()[0];
        assert_eq!(
            authored_procedure_summary_from_compiled(summary).concurrency_effects,
            expected
        );

        for (effects, expected_code) in [
            (
                vec![spawn.clone(), spawn],
                "summary.duplicate_concurrency_effect",
            ),
            (
                vec![AuthoredConcurrencyEffect::TaskSpawn {
                    callable: AuthoredSummaryInput::Receiver {},
                    group: None,
                    condition: None,
                    timer: None,
                }],
                "summary.invalid_task_callable",
            ),
            (
                vec![AuthoredConcurrencyEffect::WaitGroupAdd {
                    group: AuthoredSummaryInput::Parameter { ordinal: 0 },
                    delta: AuthoredSummaryInput::Parameter { ordinal: 0 },
                }],
                "summary.conflicting_concurrency_effect",
            ),
            (
                vec![AuthoredConcurrencyEffect::Unsupported {
                    protocol: " ".to_owned(),
                }],
                "summary.invalid_unsupported_concurrency_protocol",
            ),
            (
                vec![AuthoredConcurrencyEffect::OnceDo {
                    once: AuthoredSummaryInput::Receiver {},
                    callable: AuthoredSummaryInput::Receiver {},
                }],
                "summary.invalid_once_callable",
            ),
            (
                vec![AuthoredConcurrencyEffect::OnceDo {
                    once: AuthoredSummaryInput::Parameter { ordinal: 0 },
                    callable: AuthoredSummaryInput::Parameter { ordinal: 0 },
                }],
                "summary.conflicting_concurrency_effect",
            ),
        ] {
            let diagnostics =
                compile_pack(&with_effects(effects), &CompilerOptions::default()).unwrap_err();
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == expected_code),
                "missing {expected_code} in {diagnostics:#?}"
            );
        }
    }

    #[test]
    fn returned_callable_channel_effect_requires_schema_eleven_and_valid_results() {
        fn with_returned_callable(result_ordinal: u32) -> AuthoredSemanticModelPack {
            let mut authored: AuthoredSemanticModelPack =
                serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
            authored.schema_version = SEMANTIC_MODEL_SCHEMA_VERSION;
            authored.compatibility.bifrost = None;
            let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
            else {
                unreachable!()
            };
            let summary = &mut summaries[1];
            summary.normal_result_count = Some(2);
            summary.returned_callables = vec![AuthoredReturnedCallable {
                result_ordinal,
                at_most_once: false,
                concurrency_effects: vec![AuthoredConcurrencyEffect::ChannelClose {
                    channel: AuthoredSummaryPort::Output {
                        output: AuthoredSummaryOutput::IndexedNormalReturn { ordinal: 0 },
                    },
                    fresh: false,
                }],
            }];
            authored
        }

        let authored = with_returned_callable(1);
        let expected = match &authored.shards[0].payload {
            AuthoredPayload::ProcedureSummaries { summaries } => {
                summaries[1].returned_callables.clone()
            }
            _ => unreachable!(),
        };
        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let summary = &decoded.payload().procedure_summaries().unwrap()[1];
        assert_eq!(
            authored_procedure_summary_from_compiled(summary).returned_callables,
            expected
        );

        let mut old_schema = authored.clone();
        old_schema.schema_version = CHANNEL_CLOSE_EFFECTS_MIN_SCHEMA_VERSION - 1;
        assert!(
            compile_pack(&old_schema, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code == "summary.channel_close_schema_version")
        );

        let invalid_ordinal = with_returned_callable(2);
        assert!(
            compile_pack(&invalid_ordinal, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code == "summary.invalid_returned_callable_ordinal")
        );

        let mut self_target = with_returned_callable(1);
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut self_target.shards[0].payload
        else {
            unreachable!()
        };
        let AuthoredConcurrencyEffect::ChannelClose { channel, .. } =
            &mut summaries[1].returned_callables[0].concurrency_effects[0]
        else {
            unreachable!()
        };
        *channel = AuthoredSummaryPort::Output {
            output: AuthoredSummaryOutput::IndexedNormalReturn { ordinal: 1 },
        };
        assert!(
            compile_pack(&self_target, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| {
                    diagnostic.code == "summary.invalid_returned_callable_effect_target"
                })
        );
    }

    #[test]
    fn ordinary_heap_unchanged_defaults_omits_and_round_trips() {
        let mut authored: AuthoredSemanticModelPack =
            serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
        else {
            unreachable!()
        };
        assert!(
            summaries
                .iter()
                .all(|summary| !summary.ordinary_heap_unchanged)
        );
        let mut summary = summaries[1].clone();
        summary.ordinary_heap_unchanged = true;
        summary.effects.clear();
        let expected = summary.clone();
        summaries[1] = summary;

        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let summary = &decoded.payload().procedure_summaries().unwrap()[1];
        assert!(summary.ordinary_heap_unchanged);
        assert_eq!(authored_procedure_summary_from_compiled(summary), expected);
        assert!(
            String::from_utf8(canonical_json(summary).unwrap())
                .unwrap()
                .contains("\"ordinary_heap_unchanged\":true")
        );

        let decoded_default = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        assert!(
            !decoded_default.payload().procedure_summaries().unwrap()[0].ordinary_heap_unchanged
        );
        assert!(
            !String::from_utf8(
                canonical_json(&decoded_default.payload().procedure_summaries().unwrap()[0])
                    .unwrap(),
            )
            .unwrap()
            .contains("ordinary_heap_unchanged")
        );
    }

    #[test]
    fn ordinary_heap_unchanged_rejects_incomplete_and_conflicting_claims() {
        fn with_claim(
            mutate: impl FnOnce(&mut AuthoredProcedureSummary),
        ) -> AuthoredSemanticModelPack {
            let mut authored: AuthoredSemanticModelPack =
                serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
            let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
            else {
                unreachable!()
            };
            summaries[1].ordinary_heap_unchanged = true;
            summaries[1].effects.clear();
            mutate(&mut summaries[1]);
            authored
        }

        let call = AuthoredSummaryEffect::Call {
            event: "event.wrapper.call".to_owned(),
            callee: "summary.helper".to_owned(),
        };
        let escape = AuthoredSummaryEffect::Escape {
            event: "event.wrapper.escape".to_owned(),
            input: AuthoredSummaryInput::Parameter { ordinal: 0 },
        };
        let unknown = AuthoredSummaryEffect::UnknownCallBoundary {
            event: "event.wrapper.unknown".to_owned(),
        };
        let ambiguous = AuthoredSummaryEffect::AmbiguousCall {
            event: "event.wrapper.ambiguous".to_owned(),
            input: AuthoredSummaryInput::Parameter { ordinal: 0 },
            candidates: vec!["summary.helper".to_owned(), "summary.wrapper".to_owned()],
        };
        let conditional_write = AuthoredConditionalIndirectWrite {
            result_ordinal: 0,
            outcome: true,
            parameter_ordinal: 0,
            target: AuthoredIndirectWriteTarget::Pointee,
        };
        let storage_location = AuthoredSummaryLocation {
            id: "location.heap".to_owned(),
            location_kind: AuthoredSummaryLocationKind::Heap,
        };
        let storage_transfer = AuthoredSummaryTransfer {
            input: AuthoredSummaryInput::Parameter { ordinal: 0 },
            exit_kind: AuthoredSummaryExitKind::Normal,
            output: AuthoredSummaryOutput::Heap {
                location: storage_location.id.clone(),
            },
            value_transfer: None,
        };
        let receiver_transfer = AuthoredSummaryTransfer {
            input: AuthoredSummaryInput::Parameter { ordinal: 0 },
            exit_kind: AuthoredSummaryExitKind::Normal,
            output: AuthoredSummaryOutput::Receiver {},
            value_transfer: None,
        };
        let atomic_store = AuthoredConcurrencyEffect::Atomic {
            location: AuthoredSummaryInput::Parameter { ordinal: 0 },
            operation: AuthoredAtomicOperation::Store,
        };
        let spawn = AuthoredConcurrencyEffect::TaskSpawn {
            callable: AuthoredSummaryInput::Parameter { ordinal: 0 },
            group: None,
            condition: None,
            timer: None,
        };

        let cases = vec![
            (
                with_claim(|summary| summary.completeness = Completeness::Partial),
                "summary.ordinary_heap_unchanged_on_partial_summary",
            ),
            (
                with_claim(|summary| summary.effects = vec![call]),
                "summary.ordinary_heap_unchanged_conflict",
            ),
            (
                with_claim(|summary| summary.effects = vec![escape]),
                "summary.ordinary_heap_unchanged_conflict",
            ),
            (
                with_claim(|summary| summary.effects = vec![unknown]),
                "summary.ordinary_heap_unchanged_conflict",
            ),
            (
                with_claim(|summary| summary.effects = vec![ambiguous]),
                "summary.ordinary_heap_unchanged_conflict",
            ),
            (
                with_claim(|summary| {
                    summary.normal_result_count = Some(1);
                    summary.conditional_indirect_writes = vec![conditional_write];
                }),
                "summary.ordinary_heap_unchanged_conflict",
            ),
            (
                with_claim(|summary| {
                    summary.locations = vec![storage_location];
                    summary.transfers = vec![storage_transfer];
                }),
                "summary.ordinary_heap_unchanged_conflict",
            ),
            (
                with_claim(|summary| summary.transfers = vec![receiver_transfer]),
                "summary.ordinary_heap_unchanged_conflict",
            ),
            (
                with_claim(|summary| summary.concurrency_effects = vec![atomic_store]),
                "summary.ordinary_heap_unchanged_conflict",
            ),
            (
                with_claim(|summary| summary.concurrency_effects = vec![spawn]),
                "summary.ordinary_heap_unchanged_conflict",
            ),
            (
                with_claim(|summary| {
                    summary.concurrency_effects = vec![AuthoredConcurrencyEffect::Unsupported {
                        protocol: "unknown.protocol".to_owned(),
                    }]
                }),
                "summary.ordinary_heap_unchanged_conflict",
            ),
        ];
        for (pack, expected_code) in cases {
            let diagnostics = compile_pack(&pack, &CompilerOptions::default()).unwrap_err();
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == expected_code),
                "missing {expected_code} in {diagnostics:#?}"
            );
        }
    }

    #[test]
    fn no_concurrency_effects_defaults_omits_and_round_trips_independently() {
        let mut authored: AuthoredSemanticModelPack =
            serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        authored.schema_version = NO_CONCURRENCY_EFFECTS_MIN_SCHEMA_VERSION;
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
        else {
            unreachable!()
        };
        assert!(
            summaries
                .iter()
                .all(|summary| !summary.no_concurrency_effects)
        );

        let mut summary = summaries[1].clone();
        summary.effects.clear();
        summary.no_concurrency_effects = true;
        assert!(!summary.ordinary_heap_unchanged);
        let expected = summary.clone();
        summaries[1] = summary;

        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let summaries = decoded.payload().procedure_summaries().unwrap();
        assert!(summaries[1].no_concurrency_effects);
        assert!(!summaries[1].ordinary_heap_unchanged);
        assert_eq!(
            authored_procedure_summary_from_compiled(&summaries[1]),
            expected
        );
        assert!(
            String::from_utf8(canonical_json(&summaries[1]).unwrap())
                .unwrap()
                .contains("\"no_concurrency_effects\":true")
        );
        assert!(
            !String::from_utf8(canonical_json(&summaries[0]).unwrap())
                .unwrap()
                .contains("no_concurrency_effects")
        );
    }

    #[test]
    fn no_concurrency_effects_requires_schema_seven_complete_and_empty_effects() {
        fn with_claim(
            mutate: impl FnOnce(&mut AuthoredProcedureSummary),
        ) -> AuthoredSemanticModelPack {
            let mut authored: AuthoredSemanticModelPack =
                serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
            authored.schema_version = NO_CONCURRENCY_EFFECTS_MIN_SCHEMA_VERSION;
            let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
            else {
                unreachable!()
            };
            let summary = &mut summaries[1];
            summary.effects.clear();
            summary.no_concurrency_effects = true;
            mutate(summary);
            authored
        }

        let cases = [
            (
                with_claim(|summary| summary.completeness = Completeness::Partial),
                "summary.no_concurrency_effects_on_partial_summary",
            ),
            (
                with_claim(|summary| {
                    summary.concurrency_effects = vec![AuthoredConcurrencyEffect::LockAcquire {
                        lock: AuthoredSummaryInput::Parameter { ordinal: 0 },
                        mode: AuthoredLockMode::Exclusive,
                        condition: None,
                    }]
                }),
                "summary.no_concurrency_effects_conflict",
            ),
        ];
        for (pack, expected_code) in cases {
            let diagnostics = compile_pack(&pack, &CompilerOptions::default()).unwrap_err();
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == expected_code),
                "missing {expected_code} in {diagnostics:#?}"
            );
        }

        let mut old_schema: AuthoredSemanticModelPack =
            serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut old_schema.shards[0].payload
        else {
            unreachable!()
        };
        summaries[1].effects.clear();
        summaries[1].no_concurrency_effects = true;
        let diagnostics = compile_pack(&old_schema, &CompilerOptions::default()).unwrap_err();
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "summary.no_concurrency_effects_schema_version"
        }));
    }

    #[test]
    fn conditional_indirect_writes_validate_and_round_trip_canonically() {
        fn with_writes(writes: Vec<AuthoredConditionalIndirectWrite>) -> AuthoredSemanticModelPack {
            let mut authored: AuthoredSemanticModelPack =
                serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
            let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
            else {
                unreachable!()
            };
            summaries[1].normal_result_count = Some(1);
            summaries[1].conditional_indirect_writes = writes;
            authored
        }

        let write = AuthoredConditionalIndirectWrite {
            result_ordinal: 0,
            outcome: true,
            parameter_ordinal: 0,
            target: AuthoredIndirectWriteTarget::Pointee,
        };
        let compiled = compile_pack(
            &with_writes(vec![write.clone()]),
            &CompilerOptions::default(),
        )
        .expect("one in-range pointee write compiles");
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("compiled indirect write decodes");
        let summary = &decoded.payload().procedure_summaries().unwrap()[1];
        assert_eq!(
            authored_procedure_summary_from_compiled(summary).conditional_indirect_writes,
            vec![write.clone()]
        );
        assert!(
            String::from_utf8(canonical_json(summary).unwrap())
                .unwrap()
                .contains("\"conditional_indirect_writes\":[{\"result_ordinal\":0,\"outcome\":true,\"parameter_ordinal\":0,\"target\":\"pointee\"}]")
        );

        for (writes, expected_code) in [
            (
                vec![write.clone(), write],
                "summary.duplicate_conditional_indirect_write",
            ),
            (
                vec![AuthoredConditionalIndirectWrite {
                    result_ordinal: 1,
                    outcome: true,
                    parameter_ordinal: 0,
                    target: AuthoredIndirectWriteTarget::Pointee,
                }],
                "summary.result_ordinal_out_of_range",
            ),
            (
                vec![AuthoredConditionalIndirectWrite {
                    result_ordinal: 0,
                    outcome: true,
                    parameter_ordinal: 1,
                    target: AuthoredIndirectWriteTarget::Pointee,
                }],
                "summary.parameter_ordinal_out_of_range",
            ),
        ] {
            let diagnostics =
                compile_pack(&with_writes(writes), &CompilerOptions::default()).unwrap_err();
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == expected_code),
                "missing `{expected_code}` in {diagnostics:#?}"
            );
        }
    }

    #[test]
    fn shard_decoder_rejects_noncanonical_json_with_valid_digests() {
        let compiled = compile_source(
            SourceFormat::Json,
            DECLARATIONS,
            &CompilerOptions {
                compression: CompressionPolicy::AlwaysRaw,
                ..CompilerOptions::default()
            },
        )
        .unwrap();
        let artifact = &compiled.shards[0];
        let shard = decode_shard(
            &artifact.descriptor,
            &artifact.bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let raw = serde_json::to_vec_pretty(&shard).unwrap();
        let mut descriptor = artifact.descriptor.clone();
        descriptor.raw_size = raw.len() as u64;
        descriptor.stored_size = raw.len() as u64;
        descriptor.content_sha256 = content_digest(&raw);
        descriptor.stored_sha256 = content_digest(&raw);

        assert_eq!(
            decode_shard(&descriptor, &raw, &DecodeLimits::default()).unwrap_err(),
            ArtifactError::NonCanonical
        );
    }

    #[test]
    fn shard_decoder_rejects_trailing_deflate_data_with_valid_stored_digest() {
        let raw = b"{}";
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(6));
        encoder.write_all(raw).unwrap();
        let mut stored = encoder.finish().unwrap();
        stored.extend_from_slice(b"trailing");
        let descriptor = descriptor_for_test(raw, &stored, raw.len() as u64);

        assert_eq!(
            decode_shard(&descriptor, &stored, &DecodeLimits::default()).unwrap_err(),
            ArtifactError::TrailingCompressedData
        );
    }

    #[test]
    fn shard_decoder_stops_excessive_expansion_at_declared_size() {
        let raw = vec![0u8; 4096];
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(6));
        encoder.write_all(&raw).unwrap();
        let stored = encoder.finish().unwrap();
        let descriptor = descriptor_for_test(&raw, &stored, 32);

        assert_eq!(
            decode_shard(&descriptor, &stored, &DecodeLimits::default()).unwrap_err(),
            ArtifactError::LimitExceeded("raw shard byte limit")
        );
    }

    #[test]
    fn manifest_decoder_binds_metadata_and_total_record_limit() {
        let compiled = compile_source(
            SourceFormat::Json,
            DECLARATIONS,
            &CompilerOptions::default(),
        )
        .unwrap();
        let mut tampered = compiled.manifest.clone();
        tampered.provenance.source = "https://mirror.example/widget.jar".to_owned();
        let bytes = canonical_json(&tampered).unwrap();
        assert_eq!(
            decode_manifest(&bytes, &DecodeLimits::default()).unwrap_err(),
            ArtifactError::DigestMismatch("manifest content")
        );

        let limits = DecodeLimits {
            max_total_records: 2,
            ..DecodeLimits::default()
        };
        assert_eq!(
            decode_manifest(&compiled.manifest_bytes, &limits).unwrap_err(),
            ArtifactError::LimitExceeded("total record limit")
        );
    }

    #[test]
    #[hardwon(
        "#4709: a Kotlin vararg before named-only formals was rejected as a non-final keyword collector"
    )]
    fn positional_vararg_named_application_is_not_a_keyword_collector() {
        let mut source: serde_json::Value = serde_json::from_slice(DECLARATIONS).unwrap();
        source["schema_version"] = 8.into();
        source["compatibility"]
            .as_object_mut()
            .unwrap()
            .remove("bifrost");
        source["shards"][0]["payload"]["members"][0]["signature"]["parameters"] = serde_json::json!([
            {
                "name": "values", "type": {"kind": "named", "name": "java.lang.String"},
                "variadic": true, "passing_mode": "positional_or_named"
            },
            {
                "name": "separator", "type": {"kind": "named", "name": "java.lang.String"},
                "passing_mode": "named_only", "optional": true
            }
        ]);
        let compiled = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .expect("a positional vararg can accept its own name before named-only formals");
        let shard = decode_shard(
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("directional signature survives artifact validation");
        assert_eq!(shard.schema_version, 8);

        source["shards"][0]["payload"]["members"][0]["signature"]["parameters"][1]["passing_mode"] =
            "positional_or_named".into();
        let diagnostics = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .expect_err("a positional fixed formal cannot follow a positional vararg");
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "parameter.positional_after_variadic")
        );

        source["shards"][0]["payload"]["members"][0]["signature"]["parameters"][1]["passing_mode"] =
            "named_only".into();
        source["shards"][0]["payload"]["members"][0]["signature"]["parameters"][0]["passing_mode"] =
            "named_only".into();
        let diagnostics = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .expect_err("a keyword collector must still be final");
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "parameter.named_variadic_not_final")
        );
    }

    #[test]
    fn shard_decoder_rejects_rehashed_semantically_invalid_payload() {
        let compiled = compile_source(
            SourceFormat::Json,
            DECLARATIONS,
            &CompilerOptions {
                compression: CompressionPolicy::AlwaysRaw,
                ..CompilerOptions::default()
            },
        )
        .unwrap();
        let artifact = &compiled.shards[0];
        let mut wire: WireCompiledShard = serde_json::from_slice(&artifact.bytes).unwrap();
        let CompiledPayload::DeclarationFacts { types, .. } = &mut wire.payload else {
            unreachable!()
        };
        std::sync::Arc::make_mut(&mut types[0])
            .aliases
            .push("invalid alias".to_owned());
        let (descriptor, raw) = rehash_raw_descriptor(&artifact.descriptor, &wire);

        assert!(matches!(
            decode_shard(&descriptor, &raw, &DecodeLimits::default()),
            Err(ArtifactError::SemanticValidation(_))
        ));
    }

    #[test]
    fn shard_decoder_rejects_rehashed_procedure_metadata_tampering() {
        let compiled = compile_source(
            SourceFormat::Json,
            PROCEDURE_SUMMARIES,
            &CompilerOptions {
                compression: CompressionPolicy::AlwaysRaw,
                ..CompilerOptions::default()
            },
        )
        .unwrap();
        let artifact = &compiled.shards[0];
        let mut wire: WireCompiledShard = serde_json::from_slice(&artifact.bytes).unwrap();
        let CompiledPayload::ProcedureSummaries { summaries } = &mut wire.payload else {
            unreachable!()
        };
        std::sync::Arc::make_mut(&mut summaries[0]).model_id =
            "acme.procedure-summaries#summary.forged".to_owned();
        let (descriptor, raw) = rehash_raw_descriptor(&artifact.descriptor, &wire);

        let error = decode_shard(&descriptor, &raw, &DecodeLimits::default()).unwrap_err();
        assert!(
            matches!(
                &error,
                ArtifactError::InvalidDescriptor(message)
                    if message.contains("procedure summary model id")
            ),
            "unexpected decoder error: {error:?}"
        );
    }

    #[test]
    fn manifest_bound_decoder_rejects_rehashed_unbound_procedure_callee() {
        let compiled = compile_source(
            SourceFormat::Json,
            PROCEDURE_SUMMARIES,
            &CompilerOptions {
                compression: CompressionPolicy::AlwaysRaw,
                ..CompilerOptions::default()
            },
        )
        .unwrap();
        let artifact = &compiled.shards[0];
        let mut wire: WireCompiledShard = serde_json::from_slice(&artifact.bytes).unwrap();
        let CompiledPayload::ProcedureSummaries { summaries } = &mut wire.payload else {
            unreachable!()
        };
        let callee = std::sync::Arc::make_mut(&mut summaries[1])
            .effects
            .iter_mut()
            .find_map(|effect| match effect {
                CompiledSummaryEffect::Call { callee, .. } => Some(callee),
                _ => None,
            })
            .expect("fixture contains an exact call effect");
        *callee = "summary.missing".to_owned();
        std::sync::Arc::make_mut(&mut summaries[1]).content_sha256 = content_digest(
            &canonical_json(&authored_procedure_summary_from_compiled(&summaries[1])).unwrap(),
        );
        let (descriptor, raw) = rehash_raw_descriptor(&artifact.descriptor, &wire);
        let mut manifest = compiled.manifest.clone();
        manifest.shards[0] = descriptor.clone();

        assert!(matches!(
            decode_shard_for_manifest(&manifest, &descriptor, &raw, &DecodeLimits::default()),
            Err(ArtifactError::InvalidDescriptor(message))
                if message.contains("summary.missing")
        ));
    }

    #[test]
    fn manifest_inventory_keeps_declaration_and_procedure_namespaces_distinct() {
        let declaration_pack = compile_source(
            SourceFormat::Json,
            DECLARATIONS,
            &CompilerOptions::default(),
        )
        .unwrap();
        let mut manifest = declaration_pack.manifest.clone();
        let mut procedure_descriptor = declaration_pack.manifest.shards[0].clone();
        procedure_descriptor.shard_id = "summaries.forged".to_owned();
        procedure_descriptor.defined_ids.clear();
        procedure_descriptor.referenced_ids = vec!["procedure:type.widget".to_owned()];
        manifest.shards.push(procedure_descriptor);

        assert!(matches!(
            validate_manifest_inventory(&manifest),
            Err(ArtifactError::InvalidDescriptor(message))
                if message.contains("procedure:type.widget")
        ));
    }

    #[test]
    fn manifest_inventory_rejects_duplicate_procedure_targets_across_shards() {
        let compiled = compile_source(
            SourceFormat::Json,
            PROCEDURE_SUMMARIES,
            &CompilerOptions::default(),
        )
        .unwrap();
        let target_id = compiled.manifest.shards[0]
            .defined_ids
            .iter()
            .find(|id| id.starts_with(PROCEDURE_TARGET_INVENTORY_PREFIX))
            .unwrap()
            .clone();
        let mut first = compiled.manifest.shards[0].clone();
        first.defined_ids = vec![target_id.clone()];
        first.referenced_ids.clear();
        let mut second = first.clone();
        second.shard_id = "summaries.duplicate-target".to_owned();
        let mut manifest = compiled.manifest.clone();
        manifest.shards = vec![first, second];

        assert!(matches!(
            validate_manifest_inventory(&manifest),
            Err(ArtifactError::InvalidDescriptor(message))
                if message.contains(&target_id)
        ));
    }

    #[test]
    fn shard_decoder_rejects_rehashed_semantic_set_reordering() {
        let mut authored: AuthoredSemanticModelPack = serde_json::from_slice(DECLARATIONS).unwrap();
        let AuthoredPayload::DeclarationFacts { types, .. } = &mut authored.shards[0].payload
        else {
            unreachable!()
        };
        types[0]
            .aliases
            .extend(["com.acme.Alpha".to_owned(), "com.acme.Zeta".to_owned()]);
        let compiled = compile_pack(
            &authored,
            &CompilerOptions {
                compression: CompressionPolicy::AlwaysRaw,
                ..CompilerOptions::default()
            },
        )
        .unwrap();
        let artifact = &compiled.shards[0];
        let mut wire: WireCompiledShard = serde_json::from_slice(&artifact.bytes).unwrap();
        let CompiledPayload::DeclarationFacts { types, .. } = &mut wire.payload else {
            unreachable!()
        };
        std::sync::Arc::make_mut(&mut types[0]).aliases.reverse();
        let (descriptor, raw) = rehash_raw_descriptor(&artifact.descriptor, &wire);

        assert_eq!(
            decode_shard(&descriptor, &raw, &DecodeLimits::default()).unwrap_err(),
            ArtifactError::NonCanonical
        );
    }

    #[test]
    fn manifest_bound_decoder_rejects_a_different_envelope() {
        let compiled = compile_source(
            SourceFormat::Json,
            DECLARATIONS,
            &CompilerOptions::default(),
        )
        .unwrap();
        let mut manifest = compiled.manifest.clone();
        manifest.producer.name = "other-producer".to_owned();
        manifest.content_sha256 = manifest_content_digest(&manifest).unwrap();
        let artifact = &compiled.shards[0];

        assert!(matches!(
            decode_shard_for_manifest(
                &manifest,
                &artifact.descriptor,
                &artifact.bytes,
                &DecodeLimits::default()
            ),
            Err(ArtifactError::InvalidDescriptor(message))
                if message == "shard envelope does not match manifest"
        ));
    }

    fn rehash_raw_descriptor(
        descriptor: &CompiledShardDescriptor,
        wire: &WireCompiledShard,
    ) -> (CompiledShardDescriptor, Vec<u8>) {
        let raw = canonical_json(wire).unwrap();
        let shard = compiled_from_wire(wire.clone());
        let mut descriptor = descriptor.clone();
        descriptor.encoding = ArtifactEncoding::Raw;
        descriptor.raw_size = raw.len() as u64;
        descriptor.stored_size = raw.len() as u64;
        descriptor.semantic_sha256 = semantic_digest(&shard).unwrap();
        descriptor.content_sha256 = content_digest(&raw);
        descriptor.stored_sha256 = content_digest(&raw);
        (descriptor.defined_ids, descriptor.referenced_ids) = payload_inventory(&wire.payload);
        (descriptor, raw)
    }

    fn descriptor_for_test(
        raw: &[u8],
        stored: &[u8],
        declared_raw_size: u64,
    ) -> CompiledShardDescriptor {
        CompiledShardDescriptor {
            shard_id: "test.shard".to_owned(),
            payload_kind: PayloadKind::DeclarationFacts,
            routing_keys: Vec::new(),
            encoding: ArtifactEncoding::Deflate,
            raw_size: declared_raw_size,
            stored_size: stored.len() as u64,
            record_count: 0,
            defined_ids: Vec::new(),
            referenced_ids: Vec::new(),
            semantic_sha256: "0".repeat(64),
            content_sha256: content_digest(raw),
            stored_sha256: content_digest(stored),
        }
    }
}
