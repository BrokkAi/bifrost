use super::*;

fn location() -> PolicySourceLocation {
    PolicySourceLocation::span(
        WorkspaceRelativePath::new("Src/MyFile.py").unwrap(),
        PolicyByteSpan::new(0, 1).unwrap(),
        PolicyDisplayRegion::new(1, 1, 1, 2).unwrap(),
    )
}

fn configuration(id: &str, fact_id: &str) -> PolicyQueryResultRef {
    PolicyQueryResultRef::ConfigurationFact {
        location: location(),
        id: id.into(),
        fact_id: fact_id.into(),
    }
}

fn step(result: PolicyQueryResultRef) -> Result<PolicyQueryProvenanceStep, ReportValueError> {
    PolicyQueryProvenanceStep::try_new("read_file", result, None)
}

fn export(definition: PolicyExportLocalDefinition) -> PolicyQueryResultRef {
    PolicyQueryResultRef::Export {
        location: location(),
        id: "export".into(),
        form: "named".into(),
        exported_name: "Main Entry".into(),
        target_fq_name: None,
        local_definition: Some(definition),
    }
}

fn cross_domain(mitigation: PolicyDependencyMitigation) -> PolicyQueryResultRef {
    PolicyQueryResultRef::CrossDomain {
        location: location(),
        id: "cross".into(),
        operator: "join".into(),
        domain: "configuration".into(),
        code_id: None,
        configuration_id: None,
        configuration_location: None,
        dependency_mitigation: Some(mitigation),
    }
}

#[test]
fn configuration_fact_ids_require_identifier_spelling() {
    assert!(matches!(
        step(configuration("fact-x", "fact id")),
        Err(ReportValueError::InvalidIdentifier)
    ));
}

#[test]
fn workspace_path_wire_form_preserves_case() {
    let result = PolicyQueryResultRef::file(WorkspaceRelativePath::new("Src/MyFile.py").unwrap());
    let json = serde_json::to_string(&result).unwrap();
    let restored: PolicyQueryResultRef = serde_json::from_str(&json).unwrap();
    assert_eq!(
        serde_json::to_value(restored).unwrap()["path"],
        "Src/MyFile.py"
    );
}

#[test]
fn export_binding_keeps_display_name_and_kind_and_requires_span() {
    let defined = PolicyExportLocalDefinition::Defined {
        binding_name: "Main Entry".into(),
        binding_kind: "class_def".into(),
        binding_location: location(),
    };
    let result = step(export(defined)).unwrap();
    let json = serde_json::to_value(result.result()).unwrap();
    assert_eq!(json["local_definition"]["binding_name"], "Main Entry");
    assert_eq!(json["local_definition"]["binding_kind"], "class_def");
    let without_span = PolicyExportLocalDefinition::Defined {
        binding_name: "Main Entry".into(),
        binding_kind: "class_def".into(),
        binding_location: PolicySourceLocation::artifact(
            WorkspaceRelativePath::new("Src/MyFile.py").unwrap(),
        ),
    };
    assert!(matches!(
        step(export(without_span)),
        Err(ReportValueError::ResultLocationMustHaveSpan)
    ));
}

#[test]
fn dependency_mitigation_accepts_prose_owner_and_preserves_mapping_id() {
    let mut mitigation = PolicyDependencyMitigation {
        dependency_id: "dep".into(),
        owner: "Platform Team".into(),
        mapping_id: "map-a".into(),
        mitigated: true,
        effective_configuration: None,
        configuration_contributors: vec![],
    };
    let result = step(cross_domain(mitigation.clone())).unwrap();
    let json = serde_json::to_value(result.result()).unwrap();
    assert_eq!(json["dependency_mitigation"]["owner"], "Platform Team");
    assert_eq!(json["dependency_mitigation"]["mapping_id"], "map-a");
    mitigation.configuration_contributors = vec![location(); 4096];
    assert!(step(cross_domain(mitigation.clone())).is_ok());
    mitigation.configuration_contributors.push(location());
    assert!(matches!(
        step(cross_domain(mitigation)),
        Err(ReportValueError::TooManyItems {
            field: "configuration_contributors",
            max_items: 4096
        })
    ));
}

#[test]
fn authored_closure_accepts_nonzero_versions_and_preserves_them() {
    assert!(AuthoredArmClosureEvidence::try_new("model", "digest", 0).is_err());
    for version in [2, 7] {
        let closure = AuthoredArmClosureEvidence::try_new("model", "digest", version).unwrap();
        assert_eq!(closure.contract_version(), version);
        assert!(
            matches!(closure.to_proof_reason(), ProofReason::AuthoredArmClosure { contract_version, .. } if contract_version == version)
        );
    }
}

#[test]
fn excess_proof_reasons_name_the_reasons_limit() {
    let reasons = vec![ProofReason::DirectStructuralMatch; MAX_TYPED_REASONS + 1];
    assert!(matches!(
        ProofMetadata::try_new(ProofState::Proven, reasons, vec![]),
        Err(ReportValueError::TooManyItems {
            field: "proof_reasons",
            max_items: MAX_TYPED_REASONS
        })
    ));
}

fn ancestry_basis(
    declared_bases: Vec<brokk_bifrost_analysis::analyzer::semantic_model::TypeRef>,
    bases: Vec<Option<brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonModeledClassIdentity>>,
) -> PythonAncestryBasis {
    use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::{
        PythonModeledClassIdentity, PythonRuntimeBaseClaim,
    };
    let digest = "0".repeat(64);
    let provenance = serde_json::from_value(serde_json::json!({
        "active_model_set_hash": digest,
        "pack_digest": digest,
        "pack_id": "test.pack",
        "pack_version": "1.0.0",
        "producer": "test",
        "producer_version": "1.0.0",
        "record_id": "record",
        "origin": "dependency_source",
        "activation": {
            "status": "active", "reason": "test", "source_kind": "test", "source_id": "test",
            "matched_evidence": {"language": "python", "ecosystem": "python"}
        },
        "proof": "pack_fact", "completeness": "partial", "ambiguous": false
    }))
    .unwrap();
    PythonAncestryBasis {
        claims: vec![PythonRuntimeBaseClaim {
            declared_class: PythonModeledClassIdentity {
                qualified_name: "pkg.Root".into(),
                symbol_id: "root".into(),
            },
            class: None,
            declared_bases,
            bases,
            provenance,
        }],
    }
}

fn hierarchy(basis: PythonAncestryBasis) -> Result<PolicyQueryProvenanceStep, ReportValueError> {
    step(PolicyQueryResultRef::PythonHierarchyFact {
        id: "fact".into(),
        root_id: "root".into(),
        declaration_id: None,
        owner_id: None,
        target_id: None,
        target_owner_id: None,
        fact_kind: "base".into(),
        outcome: "unknown".into(),
        coverage: "open".into(),
        reason: None,
        location: location(),
        ancestry_basis: basis,
    })
}

#[test]
fn ancestry_declared_and_resolved_bases_are_positional() {
    use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;
    let basis = ancestry_basis(vec![TypeRef::Unknown, TypeRef::Unknown], vec![None]);
    assert!(matches!(
        hierarchy(basis),
        Err(ReportValueError::InvalidIdentifier)
    ));
}

#[test]
fn ancestry_type_references_obey_evidence_byte_limit() {
    use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;
    let long = "T".repeat(MAX_REPORT_PROSE_BYTES);
    let nested = TypeRef::Named {
        name: "Key".into(),
        arguments: vec![TypeRef::TypeParameter { name: long }; 20],
        nullable: false,
    };
    let map = TypeRef::Map {
        key: Box::new(nested.clone()),
        value: Box::new(TypeRef::Unknown),
    };
    let projection = TypeRef::Projection {
        owner: Box::new(TypeRef::Unknown),
        trait_type: Some(Box::new(nested)),
        name: "Item".into(),
        arguments: vec![],
    };
    for reference in [map, projection] {
        assert!(matches!(
            hierarchy(ancestry_basis(vec![reference], vec![None])),
            Err(ReportValueError::TooManyBytes {
                field: "python_ancestry_basis",
                ..
            })
        ));
    }
}

#[test]
fn ancestry_modeled_identity_text_obeys_evidence_byte_limit() {
    use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;
    use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonModeledClassIdentity;
    for oversized_names in [false, true] {
        let bases = (0..20)
            .map(|_| {
                Some(PythonModeledClassIdentity {
                    qualified_name: if oversized_names {
                        "N".repeat(MAX_REPORT_PROSE_BYTES)
                    } else {
                        "pkg.Base".into()
                    },
                    symbol_id: if oversized_names {
                        "base".into()
                    } else {
                        "s".repeat(MAX_REPORT_PROSE_BYTES)
                    },
                })
            })
            .collect();
        assert!(matches!(
            hierarchy(ancestry_basis(vec![TypeRef::Unknown; 20], bases)),
            Err(ReportValueError::TooManyBytes {
                field: "python_ancestry_basis",
                ..
            })
        ));
    }
}

#[test]
fn proof_reason_text_obeys_evidence_byte_limit() {
    let reasons = (0..20)
        .map(|index| ProofReason::AuthoredArmClosure {
            model: format!("{index:02}{}", "M".repeat(MAX_REPORT_PROSE_BYTES - 2)),
            content: "digest".into(),
            contract_version: 1,
        })
        .collect();
    assert!(matches!(
        ProofMetadata::try_new(ProofState::Proven, reasons, vec![]),
        Err(ReportValueError::TooManyBytes {
            field: "proof_metadata",
            ..
        })
    ));
}

#[test]
fn query_provenance_counts_each_owned_result_field() {
    let retained = |result: PolicyQueryResultRef, via: Option<PolicyQueryResultRef>| {
        let step = PolicyQueryProvenanceStep::try_new("read_file", result, via).unwrap();
        PolicyQueryProvenance::try_new(
            vec![],
            PolicyQueryResultRef::file(WorkspaceRelativePath::new("src/a.py").unwrap()),
            vec![step],
        )
        .unwrap()
        .retained_size()
    };
    let file = || PolicyQueryResultRef::file(WorkspaceRelativePath::new("src/a.py").unwrap());
    let long_id = "a".repeat(MAX_REPORT_IDENTIFIER_BYTES);
    let extra_bytes = long_id.len() - 1;

    let short_via = retained(file(), Some(configuration("a", "b")));
    let long_via = retained(file(), Some(configuration(&long_id, "b")));
    assert_eq!(long_via, short_via + extra_bytes);

    let short_fact = retained(configuration("fact", "a"), None);
    let long_fact = retained(configuration("fact", &long_id), None);
    assert_eq!(long_fact, short_fact + extra_bytes);

    let generation = |ast_id: &str| PolicyQueryResultRef::GenerationSite {
        location: location(),
        id: "site".into(),
        ast_id: Some(ast_id.into()),
        kind: "call".into(),
    };
    let short_ast = retained(generation("a"), None);
    let long_ast = retained(generation(&long_id), None);
    assert_eq!(long_ast, short_ast + extra_bytes);
}

#[test]
fn dependency_configuration_bytes_obey_query_provenance_limit() {
    let mitigation = PolicyDependencyMitigation {
        dependency_id: "dep".into(),
        owner: "Platform Team".into(),
        mapping_id: "map-a".into(),
        mitigated: true,
        effective_configuration: Some(serde_json::json!({"payload": "x".repeat(70_000)})),
        configuration_contributors: vec![],
    };
    let evidence = step(cross_domain(mitigation)).unwrap();
    assert!(matches!(
        PolicyQueryProvenance::try_new(
            vec![],
            PolicyQueryResultRef::file(WorkspaceRelativePath::new("src/a.py").unwrap()),
            vec![evidence],
        ),
        Err(ReportValueError::TooManyBytes {
            field: "query_provenance",
            ..
        })
    ));
}
