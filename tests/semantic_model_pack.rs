use brokk_bifrost::analyzer::semantic_model::*;

const DECLARATIONS_YAML: &[u8] =
    include_bytes!("fixtures/semantic-model-packs/declarations-v1.yaml");
const DECLARATIONS_JSON: &[u8] =
    include_bytes!("fixtures/semantic-model-packs/declarations-v1.json");
const RULES_YAML: &[u8] = include_bytes!("fixtures/semantic-model-packs/generator-rules-v1.yaml");
const RULES_JSON: &[u8] = include_bytes!("fixtures/semantic-model-packs/generator-rules-v1.json");

fn compile(format: SourceFormat, source: &[u8]) -> CompiledSemanticModelPack {
    compile_source(format, source, &CompilerOptions::default())
        .unwrap_or_else(|diagnostics| panic!("compilation failed: {diagnostics:#?}"))
}

fn authored_declarations() -> AuthoredSemanticModelPack {
    serde_json::from_slice(DECLARATIONS_JSON).expect("fixture is strict JSON")
}

#[test]
fn yaml_json_and_typed_inputs_compile_identically() {
    let yaml = compile(SourceFormat::Yaml, DECLARATIONS_YAML);
    let json = compile(SourceFormat::Json, DECLARATIONS_JSON);
    let typed = compile_pack(&authored_declarations(), &CompilerOptions::default()).unwrap();

    assert_eq!(yaml, json);
    assert_eq!(json, typed);
    assert_eq!(yaml.shards.len(), 1);
    assert_eq!(
        yaml.shards[0].descriptor.payload_kind,
        PayloadKind::DeclarationFacts
    );
}

#[test]
fn generator_rule_yaml_and_json_compile_identically() {
    let yaml = compile(SourceFormat::Yaml, RULES_YAML);
    let json = compile(SourceFormat::Json, RULES_JSON);

    assert_eq!(yaml, json);
    assert_eq!(
        yaml.shards[0].descriptor.payload_kind,
        PayloadKind::GeneratorRules
    );
    assert!(
        yaml.shards[0]
            .descriptor
            .routing_keys
            .contains(&"trigger:annotation".to_owned())
    );
}

#[test]
fn source_order_comments_and_formatting_are_semantically_neutral() {
    let baseline = compile(SourceFormat::Yaml, DECLARATIONS_YAML);
    let mut source = String::from("# reviewed source comment\n");
    source.push_str(std::str::from_utf8(DECLARATIONS_YAML).unwrap());
    let commented = compile(SourceFormat::Yaml, source.as_bytes());

    let mut authored = authored_declarations();
    authored.compatibility.toolchains.reverse();
    authored.shards.reverse();
    authored.shards[0].activation[0].targets.reverse();
    let reordered = compile_pack(&authored, &CompilerOptions::default()).unwrap();

    assert_eq!(baseline, commented);
    assert_eq!(baseline, reordered);
}

#[test]
fn ordered_parameter_changes_semantic_identity() {
    let mut authored = authored_declarations();
    {
        let AuthoredPayload::DeclarationFacts { members, .. } = &mut authored.shards[0].payload
        else {
            unreachable!()
        };
        members[0]
            .signature
            .as_mut()
            .unwrap()
            .parameters
            .push(Parameter {
                name: "second".to_owned(),
                r#type: TypeRef::Named {
                    id: "java.lang.Integer".to_owned(),
                    arguments: Vec::new(),
                    nullable: false,
                },
                optional: false,
                variadic: false,
            });
    }
    let first = compile_pack(&authored, &CompilerOptions::default()).unwrap();
    let AuthoredPayload::DeclarationFacts { members, .. } = &mut authored.shards[0].payload else {
        unreachable!()
    };
    members[0].signature.as_mut().unwrap().parameters.reverse();
    let reversed = compile_pack(&authored, &CompilerOptions::default()).unwrap();

    assert_ne!(
        first.manifest.semantic_sha256,
        reversed.manifest.semantic_sha256
    );
}

#[test]
fn malformed_model_reports_sorted_semantic_diagnostics() {
    let diagnostics = compile_source(
        SourceFormat::Yaml,
        include_bytes!("fixtures/semantic-model-packs/malformed-v1.yaml"),
        &CompilerOptions::default(),
    )
    .unwrap_err();

    assert!(
        diagnostics
            .iter()
            .any(|d| d.code == "schema.unsupported_version")
    );
    assert!(diagnostics.iter().any(|d| d.code == "license.invalid_spdx"));
    assert!(diagnostics.iter().any(|d| d.code == "identifier.invalid"));
    assert!(
        diagnostics
            .windows(2)
            .all(|pair| { (&pair[0].path, &pair[0].code) <= (&pair[1].path, &pair[1].code) })
    );
}

#[test]
fn unknown_fields_versions_and_yaml_extensions_are_rejected() {
    let future = br#"{"schema_version":2,"unknown":true}"#;
    assert_eq!(
        compile_source(SourceFormat::Json, future, &CompilerOptions::default()).unwrap_err()[0]
            .code,
        "source.parse"
    );

    for yaml in [
        "schema_version: 1\nschema_version: 1\n",
        "base: &base {schema_version: 1}\ncopy: *base\n",
        "base: &base {schema_version: 1}\npack: {<<: *base}\n",
        "---\nschema_version: 1\n---\nschema_version: 1\n",
    ] {
        assert!(
            compile_source(
                SourceFormat::Yaml,
                yaml.as_bytes(),
                &CompilerOptions::default()
            )
            .is_err()
        );
    }
}

#[test]
fn capture_type_cardinality_and_identifier_errors_are_aggregated() {
    let mut authored: AuthoredSemanticModelPack = serde_json::from_slice(RULES_JSON).unwrap();
    let AuthoredPayload::GeneratorRules { rules } = &mut authored.shards[0].payload else {
        unreachable!()
    };
    rules[0].captures[0].cardinality = CaptureCardinality::Many;
    rules[0].captures[1].value_kind = CaptureValueKind::String;
    rules[0].emissions.push(RuleEmission::Alias {
        id: TemplateExpression::Literal {
            value: "INVALID ID".to_owned(),
        },
        from: TemplateExpression::Capture {
            name: "missing".to_owned(),
        },
        to: TemplateExpression::Capture {
            name: "entity".to_owned(),
        },
    });
    let diagnostics = compile_pack(&authored, &CompilerOptions::default()).unwrap_err();

    assert!(diagnostics.iter().any(|d| d.code == "capture.cardinality"));
    assert!(
        diagnostics
            .iter()
            .any(|d| d.code == "capture.type_mismatch")
    );
    assert!(diagnostics.iter().any(|d| d.code == "capture.unknown"));
    assert!(
        diagnostics
            .iter()
            .any(|d| d.code == "template.invalid_identifier_literal")
    );
}

#[test]
fn raw_and_deflate_storage_preserve_semantic_and_content_identity() {
    let authored = authored_declarations();
    let raw = compile_pack(
        &authored,
        &CompilerOptions {
            compression: CompressionPolicy::AlwaysRaw,
            ..CompilerOptions::default()
        },
    )
    .unwrap();
    let deflate = compile_pack(
        &authored,
        &CompilerOptions {
            compression: CompressionPolicy::AlwaysDeflate,
            ..CompilerOptions::default()
        },
    )
    .unwrap();

    assert_eq!(
        raw.shards[0].descriptor.semantic_sha256,
        deflate.shards[0].descriptor.semantic_sha256
    );
    assert_eq!(
        raw.shards[0].descriptor.content_sha256,
        deflate.shards[0].descriptor.content_sha256
    );
    assert_ne!(
        raw.shards[0].descriptor.stored_sha256,
        deflate.shards[0].descriptor.stored_sha256
    );
    assert_eq!(
        decode_shard(
            &raw.shards[0].descriptor,
            &raw.shards[0].bytes,
            &DecodeLimits::default()
        )
        .unwrap(),
        decode_shard(
            &deflate.shards[0].descriptor,
            &deflate.shards[0].bytes,
            &DecodeLimits::default()
        )
        .unwrap()
    );
}

#[test]
fn manifest_and_shard_decoders_reject_corruption_and_caps() {
    let compiled = compile(SourceFormat::Json, DECLARATIONS_JSON);
    assert_eq!(
        decode_manifest(&compiled.manifest_bytes, &DecodeLimits::default()).unwrap(),
        compiled.manifest
    );

    let mut pretty = serde_json::to_vec_pretty(&compiled.manifest).unwrap();
    pretty.push(b'\n');
    assert_eq!(
        decode_manifest(&pretty, &DecodeLimits::default()).unwrap_err(),
        ArtifactError::NonCanonical
    );

    let artifact = &compiled.shards[0];
    let mut corrupt = artifact.bytes.clone();
    corrupt[0] ^= 1;
    assert_eq!(
        decode_shard(&artifact.descriptor, &corrupt, &DecodeLimits::default()).unwrap_err(),
        ArtifactError::DigestMismatch("stored")
    );

    let mut limits = DecodeLimits::default();
    limits.max_raw_shard_bytes = 1;
    assert_eq!(
        decode_shard(&artifact.descriptor, &artifact.bytes, &limits).unwrap_err(),
        ArtifactError::LimitExceeded("raw shard byte limit")
    );
}

#[test]
fn checked_in_json_schema_matches_rust_model() {
    assert_eq!(
        include_str!("../schemas/semantic-model-pack-v1.schema.json"),
        authoring_json_schema()
    );
}

#[test]
fn checked_in_golden_artifacts_are_exact_and_decodable() {
    for (source, policy, manifest, shard) in [
        (
            DECLARATIONS_JSON,
            CompressionPolicy::AlwaysRaw,
            include_bytes!("fixtures/semantic-model-packs/declarations-v1.manifest.json")
                .as_slice(),
            include_bytes!("fixtures/semantic-model-packs/declarations-v1.shard.json").as_slice(),
        ),
        (
            RULES_JSON,
            CompressionPolicy::AlwaysDeflate,
            include_bytes!("fixtures/semantic-model-packs/generator-rules-v1.manifest.json")
                .as_slice(),
            include_bytes!("fixtures/semantic-model-packs/generator-rules-v1.shard.deflate")
                .as_slice(),
        ),
    ] {
        let compiled = compile_source(
            SourceFormat::Json,
            source,
            &CompilerOptions {
                compression: policy,
                ..CompilerOptions::default()
            },
        )
        .unwrap();
        assert_eq!(compiled.manifest_bytes, manifest);
        assert_eq!(compiled.shards[0].bytes, shard);

        let decoded_manifest = decode_manifest(manifest, &DecodeLimits::default()).unwrap();
        let decoded_shard =
            decode_shard(&decoded_manifest.shards[0], shard, &DecodeLimits::default()).unwrap();
        assert_eq!(decoded_shard.pack_id, decoded_manifest.pack_id);
    }
}

#[test]
fn cross_shard_references_are_resolved_after_global_collection() {
    let mut authored = authored_declarations();
    let activation = authored.shards[0].activation.clone();
    let AuthoredPayload::DeclarationFacts {
        types,
        members: _,
        relations: _,
    } = &mut authored.shards[0].payload
    else {
        unreachable!()
    };
    let moved_types = std::mem::take(types);
    authored.shards.push(AuthoredShard {
        id: "declarations.widget-types".to_owned(),
        activation,
        payload: AuthoredPayload::DeclarationFacts {
            types: moved_types,
            members: Vec::new(),
            relations: Vec::new(),
        },
    });

    compile_pack(&authored, &CompilerOptions::default()).unwrap();
}

#[test]
fn source_record_depth_and_selector_limits_fail_closed() {
    let source_error = compile_source(
        SourceFormat::Json,
        DECLARATIONS_JSON,
        &CompilerOptions {
            max_source_bytes: 1,
            ..CompilerOptions::default()
        },
    )
    .unwrap_err();
    assert_eq!(source_error[0].code, "limit.source_bytes");

    let mut authored = authored_declarations();
    let AuthoredPayload::DeclarationFacts { types, .. } = &mut authored.shards[0].payload else {
        unreachable!()
    };
    let mut nested = TypeRef::Named {
        id: "java.lang.String".to_owned(),
        arguments: Vec::new(),
        nullable: false,
    };
    for _ in 0..4 {
        nested = TypeRef::Array {
            element: Box::new(nested),
        };
    }
    types[0].supertypes.push(nested);
    authored.shards[0].activation[0].toolchain = Some(NameSelector {
        name: "unknown-toolchain".to_owned(),
        version: Some(">=1.0.0".to_owned()),
    });
    let diagnostics = compile_pack(
        &authored,
        &CompilerOptions {
            max_records_per_shard: 2,
            max_depth: 3,
            ..CompilerOptions::default()
        },
    )
    .unwrap_err();

    assert!(diagnostics.iter().any(|d| d.code == "limit.shard_records"));
    assert!(diagnostics.iter().any(|d| d.code == "limit.type_depth"));
    assert!(
        diagnostics
            .iter()
            .any(|d| d.code == "selector.incompatible")
    );
}
