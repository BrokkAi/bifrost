use brokk_bifrost::analyzer::semantic_model::*;

const DECLARATIONS_YAML: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/declarations-v1.yaml");
const DECLARATIONS_JSON: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/declarations-v1.json");
const RULES_YAML: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/generator-rules-v1.yaml");
const RULES_JSON: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/generator-rules-v1.json");
const PROCEDURES_YAML: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/procedure-summaries-v1.yaml");
const PROCEDURES_JSON: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/procedure-summaries-v1.json");

fn compile(format: SourceFormat, source: &[u8]) -> CompiledSemanticModelPack {
    compile_source(format, source, &CompilerOptions::default())
        .unwrap_or_else(|diagnostics| panic!("compilation failed: {diagnostics:#?}"))
}

fn authored_declarations() -> AuthoredSemanticModelPack {
    serde_json::from_slice(DECLARATIONS_JSON).expect("fixture is strict JSON")
}

fn authored_procedures() -> AuthoredSemanticModelPack {
    serde_json::from_slice(PROCEDURES_JSON).expect("fixture is strict JSON")
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
fn declaration_facts_preserve_structured_constraints_underlying_types_and_receivers() {
    let mut pack = authored_declarations();
    let AuthoredPayload::DeclarationFacts { types, members, .. } = &mut pack.shards[0].payload
    else {
        panic!("declaration fixture must contain declaration facts");
    };
    types[0].type_parameter_constraints = vec![TypeParameterConstraint {
        parameter: "t".to_owned(),
        constraint: StructuredTypeExpression {
            display: "comparable".to_owned(),
            referenced_types: vec![TypeRef::Named {
                name: "comparable".to_owned(),
                arguments: Vec::new(),
                nullable: false,
            }],
        },
    }];
    types[0].underlying_type = Some(StructuredTypeExpression {
        display: "struct{ Value t }".to_owned(),
        referenced_types: vec![TypeRef::TypeParameter {
            name: "t".to_owned(),
        }],
    });
    types[0].embedded_types = vec![EmbeddedTypeFact {
        target: TypeRef::Named {
            name: "io.Reader".to_owned(),
            arguments: Vec::new(),
            nullable: false,
        },
        pointer: true,
    }];
    members[0].receiver = Some(ReceiverFact { pointer: true });

    let compiled = compile_pack(&pack, &CompilerOptions::default()).unwrap();
    let decoded = decode_shard_for_manifest(
        &compiled.manifest,
        &compiled.shards[0].descriptor,
        &compiled.shards[0].bytes,
        &DecodeLimits::default(),
    )
    .unwrap();
    let (types, members, _) = decoded.payload().declaration_facts().unwrap();

    assert_eq!(types[0].type_parameter_constraints.len(), 1);
    assert_eq!(
        types[0].underlying_type.as_ref().unwrap().display,
        "struct{ Value t }"
    );
    assert!(types[0].embedded_types[0].pointer);
    assert_eq!(members[0].receiver, Some(ReceiverFact { pointer: true }));
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
fn procedure_summary_yaml_json_and_typed_inputs_compile_identically() {
    let yaml = compile(SourceFormat::Yaml, PROCEDURES_YAML);
    let json = compile(SourceFormat::Json, PROCEDURES_JSON);
    let typed = compile_pack(&authored_procedures(), &CompilerOptions::default()).unwrap();

    assert_eq!(yaml, json);
    assert_eq!(json, typed);
    assert_eq!(
        yaml.shards[0].descriptor.payload_kind,
        PayloadKind::ProcedureSummaries
    );
    assert_eq!(yaml.shards[0].descriptor.record_count, 2);
    assert!(
        yaml.shards[0]
            .descriptor
            .routing_keys
            .contains(&"payload:procedure_summaries".to_owned())
    );

    let decoded = decode_shard_for_manifest(
        &yaml.manifest,
        &yaml.shards[0].descriptor,
        &yaml.shards[0].bytes,
        &DecodeLimits::default(),
    )
    .unwrap();
    let summaries = decoded.payload().procedure_summaries().unwrap();
    assert_eq!(summaries.len(), 2);
    assert_eq!(summaries[0].id, "summary.helper");
    assert_eq!(
        summaries[0].model_id,
        "acme.procedure-summaries#summary.helper"
    );
    assert_eq!(
        summaries[0].contract_version,
        PROCEDURE_SUMMARY_CONTRACT_VERSION
    );
    assert_eq!(summaries[0].content_sha256.len(), 64);
    assert_eq!(summaries[0].target.path, "com/acme/Flows.class");
    assert_eq!(summaries[0].completeness, Completeness::Partial);
    assert_eq!(summaries[1].completeness, Completeness::Complete);

    let raw = if yaml.shards[0].descriptor.encoding == ArtifactEncoding::Raw {
        yaml.shards[0].bytes.clone()
    } else {
        serde_json::to_vec(&decoded).unwrap()
    };
    let rendered = String::from_utf8(raw).unwrap();
    for forbidden in [
        "/Users/",
        "/tmp/",
        "/private/tmp/",
        "workspace_mount",
        "procedure_handle",
        "context_key",
        "behavior_key",
        "dependency_fingerprint",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "compiled target leaked `{forbidden}`"
        );
    }
}

#[test]
fn procedure_summary_semantic_sets_are_order_independent() {
    let baseline = compile_pack(&authored_procedures(), &CompilerOptions::default()).unwrap();
    let mut authored = authored_procedures();
    let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload else {
        unreachable!()
    };
    summaries.reverse();
    for summary in summaries {
        summary.locations.reverse();
        summary.transfers.reverse();
        summary.effects.reverse();
        for effect in &mut summary.effects {
            if let AuthoredSummaryEffect::AmbiguousCall { candidates, .. } = effect {
                candidates.reverse();
            }
        }
    }
    let reordered = compile_pack(&authored, &CompilerOptions::default()).unwrap();

    assert_eq!(baseline, reordered);
}

#[test]
fn ruby_mixin_hierarchy_retains_declaration_order() {
    let mut authored = authored_declarations();
    let AuthoredPayload::DeclarationFacts { types, .. } = &mut authored.shards[0].payload else {
        unreachable!()
    };
    types[0].hierarchy = vec![
        HierarchyFact {
            hierarchy_kind: HierarchyKind::MixinInclude,
            target: TypeRef::Named {
                name: "Acme::Later".to_owned(),
                arguments: Vec::new(),
                nullable: false,
            },
            declaration_ordinal: Some(1),
        },
        HierarchyFact {
            hierarchy_kind: HierarchyKind::MixinPrepend,
            target: TypeRef::Named {
                name: "Acme::First".to_owned(),
                arguments: Vec::new(),
                nullable: false,
            },
            declaration_ordinal: Some(0),
        },
        HierarchyFact {
            hierarchy_kind: HierarchyKind::MixinExtend,
            target: TypeRef::Named {
                name: "Acme::Last".to_owned(),
                arguments: Vec::new(),
                nullable: false,
            },
            declaration_ordinal: Some(2),
        },
    ];

    let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
    let decoded = decode_shard_for_manifest(
        &compiled.manifest,
        &compiled.shards[0].descriptor,
        &compiled.shards[0].bytes,
        &DecodeLimits::default(),
    )
    .unwrap();
    let hierarchy = &decoded.payload().declaration_facts().unwrap().0[0].hierarchy;

    assert_eq!(
        hierarchy
            .iter()
            .map(|fact| (fact.hierarchy_kind, fact.declaration_ordinal))
            .collect::<Vec<_>>(),
        vec![
            (HierarchyKind::MixinPrepend, Some(0)),
            (HierarchyKind::MixinInclude, Some(1)),
            (HierarchyKind::MixinExtend, Some(2)),
        ]
    );
}

#[test]
fn invalid_procedure_summary_targets_ports_locations_and_completeness_fail_closed() {
    let mut cases = Vec::new();

    let mut duplicate_target = authored_procedures();
    let AuthoredPayload::ProcedureSummaries { summaries } = &mut duplicate_target.shards[0].payload
    else {
        unreachable!()
    };
    summaries[1].target = summaries[0].target.clone();
    cases.push((duplicate_target, "summary.duplicate_target"));

    for target_path in ["C:/acme/Flows.class", "C:acme/Flows.class"] {
        let mut nonportable_target = authored_procedures();
        let AuthoredPayload::ProcedureSummaries { summaries } =
            &mut nonportable_target.shards[0].payload
        else {
            unreachable!()
        };
        summaries[0].target.path = target_path.to_owned();
        cases.push((nonportable_target, "locator.invalid_path"));
    }

    let mut invalid_ordinal = authored_procedures();
    let AuthoredPayload::ProcedureSummaries { summaries } = &mut invalid_ordinal.shards[0].payload
    else {
        unreachable!()
    };
    summaries[1].transfers[0].input = AuthoredSummaryInput::Parameter { ordinal: 1 };
    cases.push((invalid_ordinal, "summary.invalid_ordinal"));

    let mut missing_receiver = authored_procedures();
    let AuthoredPayload::ProcedureSummaries { summaries } = &mut missing_receiver.shards[0].payload
    else {
        unreachable!()
    };
    summaries[1].transfers[0].input = AuthoredSummaryInput::Receiver {};
    cases.push((missing_receiver, "summary.receiver_unavailable"));

    let mut incompatible_exit = authored_procedures();
    let AuthoredPayload::ProcedureSummaries { summaries } =
        &mut incompatible_exit.shards[0].payload
    else {
        unreachable!()
    };
    summaries[1].transfers[0].exit_kind = AuthoredSummaryExitKind::Exceptional;
    cases.push((incompatible_exit, "summary.incompatible_exit_port"));

    let mut missing_location = authored_procedures();
    let AuthoredPayload::ProcedureSummaries { summaries } = &mut missing_location.shards[0].payload
    else {
        unreachable!()
    };
    summaries[0].transfers[2].output = AuthoredSummaryOutput::Capture {
        location: "location.missing".to_owned(),
    };
    cases.push((missing_location, "summary.unbound_location"));

    let mut wrong_location_kind = authored_procedures();
    let AuthoredPayload::ProcedureSummaries { summaries } =
        &mut wrong_location_kind.shards[0].payload
    else {
        unreachable!()
    };
    summaries[0].locations[0].location_kind = AuthoredSummaryLocationKind::Heap;
    cases.push((wrong_location_kind, "summary.incompatible_location_kind"));

    let mut incompatible_effect = authored_procedures();
    let AuthoredPayload::ProcedureSummaries { summaries } =
        &mut incompatible_effect.shards[0].payload
    else {
        unreachable!()
    };
    let AuthoredSummaryEffect::Allocation { output, .. } = &mut summaries[0].effects[0] else {
        unreachable!()
    };
    *output = AuthoredSummaryOutput::Capture {
        location: "location.receiver-field".to_owned(),
    };
    cases.push((incompatible_effect, "summary.incompatible_location_kind"));

    let mut missing_callee = authored_procedures();
    let AuthoredPayload::ProcedureSummaries { summaries } = &mut missing_callee.shards[0].payload
    else {
        unreachable!()
    };
    let AuthoredSummaryEffect::Call { callee, .. } = &mut summaries[1].effects[0] else {
        unreachable!()
    };
    *callee = "summary.missing".to_owned();
    cases.push((missing_callee, "summary.unbound_callee"));

    let mut stronger_than_pack = authored_procedures();
    stronger_than_pack.completeness = Completeness::Partial;
    cases.push((stronger_than_pack, "summary.completeness_exceeds_pack"));

    let mut malformed_provenance = authored_procedures();
    malformed_provenance.provenance.source.clear();
    cases.push((malformed_provenance, "text.empty"));

    let mut oversized_model_id = authored_procedures();
    oversized_model_id.pack_id = "a".repeat(256);
    let AuthoredPayload::ProcedureSummaries { summaries } =
        &mut oversized_model_id.shards[0].payload
    else {
        unreachable!()
    };
    summaries[0].id = "b".repeat(256);
    cases.push((oversized_model_id, "limit.summary_model_id_bytes"));

    let mut oversized_effect_references = authored_procedures();
    let AuthoredPayload::ProcedureSummaries { summaries } =
        &mut oversized_effect_references.shards[0].payload
    else {
        unreachable!()
    };
    summaries[0].effects = vec![
        AuthoredSummaryEffect::AmbiguousCall {
            event: "event.helper.dispatch".to_owned(),
            input: AuthoredSummaryInput::Receiver {},
            candidates: vec!["summary.helper".to_owned(), "summary.wrapper".to_owned()],
        };
        MAX_PROCEDURE_SUMMARY_EFFECT_REFERENCES / 2 + 1
    ];
    cases.push((
        oversized_effect_references,
        "limit.summary_effect_references",
    ));

    let mut oversized_transfers = authored_procedures();
    let AuthoredPayload::ProcedureSummaries { summaries } =
        &mut oversized_transfers.shards[0].payload
    else {
        unreachable!()
    };
    summaries[0].transfers =
        vec![summaries[0].transfers[0].clone(); MAX_PROCEDURE_SUMMARY_TRANSFERS + 1];
    cases.push((oversized_transfers, "limit.summary_transfers"));

    for (authored, expected_code) in cases {
        let diagnostics = compile_pack(&authored, &CompilerOptions::default()).unwrap_err();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == expected_code),
            "missing `{expected_code}` in {diagnostics:#?}"
        );
    }
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
                name: Some("second".to_owned()),
                r#type: TypeRef::Named {
                    name: "java.lang.Integer".to_owned(),
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
        include_bytes!("../fixtures/semantic-model-packs/malformed-v1.yaml"),
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
fn unknown_fields_are_rejected_inside_every_tagged_variant_family() {
    for (source, pointers) in [
        (
            DECLARATIONS_JSON,
            vec![
                "/shards/0/payload",
                "/shards/0/payload/types/0/hierarchy/0/target",
            ],
        ),
        (
            RULES_JSON,
            vec![
                "/shards/0/payload/rules/0/trigger",
                "/shards/0/payload/rules/0/emissions/0/declaration",
                "/shards/0/payload/rules/0/emissions/0/id",
            ],
        ),
        (
            PROCEDURES_JSON,
            vec![
                "/shards/0/payload",
                "/shards/0/payload/summaries/0/target",
                "/shards/0/payload/summaries/0/transfers/0/input",
                "/shards/0/payload/summaries/0/transfers/0/output",
                "/shards/0/payload/summaries/0/effects/0",
            ],
        ),
    ] {
        for pointer in pointers {
            let mut value: serde_json::Value = serde_json::from_slice(source).unwrap();
            value
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
            let encoded = serde_json::to_vec(&value).unwrap();
            for format in [SourceFormat::Json, SourceFormat::Yaml] {
                let diagnostics =
                    compile_source(format, &encoded, &CompilerOptions::default()).unwrap_err();
                assert_eq!(
                    diagnostics[0].code, "source.parse",
                    "{format:?} accepted unknown field at {pointer}"
                );
            }
        }
    }
}

#[test]
fn schema_pins_version_one_exactly() {
    let schema: serde_json::Value = serde_json::from_str(&authoring_json_schema()).unwrap();
    let version = &schema["properties"]["schema_version"];
    assert_eq!(version["minimum"], 1);
    assert_eq!(version["maximum"], 1);
}

#[test]
fn language_names_and_owner_type_parameters_are_not_stable_ids() {
    let mut authored = authored_declarations();
    let AuthoredPayload::DeclarationFacts { types, members, .. } = &mut authored.shards[0].payload
    else {
        unreachable!()
    };
    types[0].type_parameters = vec!["TValue".to_owned()];
    members[0].name = "getURL".to_owned();
    let signature = members[0].signature.as_mut().unwrap();
    signature.parameters[0].name = Some("_value".to_owned());
    signature.returns = Some(TypeRef::TypeParameter {
        name: "TValue".to_owned(),
    });

    compile_pack(&authored, &CompilerOptions::default()).unwrap();
}

#[test]
fn binary_signatures_can_omit_parameter_names() {
    let mut authored = authored_declarations();
    let AuthoredPayload::DeclarationFacts { members, .. } = &mut authored.shards[0].payload else {
        unreachable!()
    };
    members[0].signature.as_mut().unwrap().parameters[0].name = None;

    let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
    let decoded = decode_shard_for_manifest(
        &compiled.manifest,
        &compiled.shards[0].descriptor,
        &compiled.shards[0].bytes,
        &DecodeLimits::default(),
    )
    .unwrap();
    let members = decoded.payload().declaration_facts().unwrap().1;
    assert_eq!(
        members[0].signature.as_ref().unwrap().parameters[0].name,
        None
    );
}

#[test]
fn capture_type_cardinality_and_identifier_errors_are_aggregated() {
    let mut authored: AuthoredSemanticModelPack = serde_json::from_slice(RULES_JSON).unwrap();
    let AuthoredPayload::GeneratorRules { rules } = &mut authored.shards[0].payload else {
        unreachable!()
    };
    rules[0].captures[0].cardinality = CaptureCardinality::Many;
    rules[0].captures[2].value_kind = CaptureValueKind::String;
    rules[0].emissions.push(RuleEmission::Alias {
        id: TemplateExpression::Literal {
            value: "INVALID ID".to_owned(),
        },
        from: TemplateExpression::Capture {
            name: "missing".to_owned(),
        },
        to: TemplateExpression::Capture {
            name: "owner_id".to_owned(),
        },
    });
    let diagnostics = compile_pack(&authored, &CompilerOptions::default()).unwrap_err();

    assert!(
        diagnostics
            .iter()
            .any(|d| d.code == "capture.binding_cardinality_mismatch")
    );
    assert!(
        diagnostics
            .iter()
            .any(|d| d.code == "capture.binding_type_mismatch")
    );
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
fn provenance_changes_content_but_not_semantic_identity() {
    let baseline = compile_pack(&authored_declarations(), &CompilerOptions::default()).unwrap();
    let mut authored = authored_declarations();
    authored.producer.name = "different-scanner".to_owned();
    authored.provenance.source = "https://mirror.example/widget.jar".to_owned();
    authored.license = "MIT".to_owned();
    let changed = compile_pack(&authored, &CompilerOptions::default()).unwrap();

    assert_eq!(
        baseline.shards[0].descriptor.semantic_sha256,
        changed.shards[0].descriptor.semantic_sha256
    );
    assert_eq!(
        baseline.manifest.semantic_sha256,
        changed.manifest.semantic_sha256
    );
    assert_ne!(
        baseline.shards[0].descriptor.content_sha256,
        changed.shards[0].descriptor.content_sha256
    );
    assert_ne!(
        baseline.manifest.content_sha256,
        changed.manifest.content_sha256
    );
}

#[test]
fn automatic_compression_uses_the_documented_threshold() {
    let mut minimal = authored_declarations();
    minimal.producer.name = "p".to_owned();
    minimal.language = "j".to_owned();
    minimal.ecosystem = "e".to_owned();
    minimal.compatibility.bifrost = "*".to_owned();
    minimal.compatibility.toolchains.clear();
    minimal.provenance.source = "s".to_owned();
    minimal.provenance.revision = None;
    minimal.shards[0].activation[0] = ActivationSelector {
        package: Some(NameSelector {
            name: "p".to_owned(),
            version: None,
        }),
        module: None,
        toolchain: None,
        targets: Vec::new(),
        configurations: Vec::new(),
        artifact_sha256: None,
    };
    let AuthoredPayload::DeclarationFacts {
        types,
        members,
        relations,
    } = &mut minimal.shards[0].payload
    else {
        unreachable!()
    };
    types[0].name = "T".to_owned();
    types[0].type_parameters.clear();
    types[0].hierarchy.clear();
    types[0].aliases.clear();
    types[0].extension_surfaces.clear();
    types[0].locator = Locator::Artifact {
        path: "T".to_owned(),
        symbol: "T".to_owned(),
    };
    members.clear();
    relations.clear();
    let small = compile_pack(&minimal, &CompilerOptions::default()).unwrap();
    assert_eq!(small.shards[0].descriptor.encoding, ArtifactEncoding::Raw);

    let mut authored = authored_declarations();
    let AuthoredPayload::DeclarationFacts { relations, .. } = &mut authored.shards[0].payload
    else {
        unreachable!()
    };
    for index in 0..200 {
        relations.push(RelationFact {
            id: format!("relation.widget.generated-{index}"),
            relation_kind: RelationKind::References,
            from: "member.widget.create".to_owned(),
            to: "type.widget".to_owned(),
        });
    }
    let large = compile_pack(&authored, &CompilerOptions::default()).unwrap();
    assert_eq!(
        large.shards[0].descriptor.encoding,
        ArtifactEncoding::Deflate
    );
}

#[test]
fn compiler_limits_keep_default_artifacts_decodable() {
    let compiled = compile_pack(&authored_declarations(), &CompilerOptions::default()).unwrap();
    let manifest = decode_manifest(&compiled.manifest_bytes, &DecodeLimits::default()).unwrap();
    decode_shard_for_manifest(
        &manifest,
        &manifest.shards[0],
        &compiled.shards[0].bytes,
        &DecodeLimits::default(),
    )
    .unwrap();

    let manifest_error = compile_pack(
        &authored_declarations(),
        &CompilerOptions {
            max_manifest_bytes: 1,
            ..CompilerOptions::default()
        },
    )
    .unwrap_err();
    assert_eq!(manifest_error[0].code, "limit.manifest_bytes");

    let stored_error = compile_pack(
        &authored_declarations(),
        &CompilerOptions {
            max_stored_shard_bytes: 1,
            compression: CompressionPolicy::AlwaysDeflate,
            ..CompilerOptions::default()
        },
    )
    .unwrap_err();
    assert_eq!(stored_error[0].code, "limit.stored_shard_bytes");
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

    let limits = DecodeLimits {
        max_raw_shard_bytes: 1,
        ..DecodeLimits::default()
    };
    assert_eq!(
        decode_shard(&artifact.descriptor, &artifact.bytes, &limits).unwrap_err(),
        ArtifactError::LimitExceeded("raw shard byte limit")
    );
}

#[test]
fn checked_in_json_schema_matches_rust_model() {
    assert_eq!(
        include_str!("../../schemas/semantic-model-pack-v1.schema.json"),
        authoring_json_schema()
    );
}

#[test]
fn checked_in_golden_artifacts_are_exact_and_decodable() {
    for (source, policy, manifest, shard) in [
        (
            DECLARATIONS_JSON,
            CompressionPolicy::AlwaysRaw,
            include_bytes!("../fixtures/semantic-model-packs/declarations-v1.manifest.json")
                .as_slice(),
            include_bytes!("../fixtures/semantic-model-packs/declarations-v1.shard.json")
                .as_slice(),
        ),
        (
            RULES_JSON,
            CompressionPolicy::AlwaysDeflate,
            include_bytes!("../fixtures/semantic-model-packs/generator-rules-v1.manifest.json")
                .as_slice(),
            include_bytes!("../fixtures/semantic-model-packs/generator-rules-v1.shard.deflate")
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
        let decoded_shard = decode_shard_for_manifest(
            &decoded_manifest,
            &decoded_manifest.shards[0],
            shard,
            &DecodeLimits::default(),
        )
        .unwrap();
        assert_eq!(decoded_shard.pack_id(), decoded_manifest.pack_id);
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
        name: "java.lang.String".to_owned(),
        arguments: Vec::new(),
        nullable: false,
    };
    for _ in 0..4 {
        nested = TypeRef::Array {
            element: Box::new(nested),
        };
    }
    types[0].hierarchy.push(HierarchyFact {
        hierarchy_kind: HierarchyKind::Extends,
        target: nested,
        declaration_ordinal: None,
    });
    authored.shards[0].activation[0].toolchain = Some(NameSelector {
        name: "unknown-toolchain".to_owned(),
        version: Some(">=1.0.0".to_owned()),
    });
    let diagnostics = compile_pack(
        &authored,
        &CompilerOptions {
            max_records_per_shard: 1,
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
