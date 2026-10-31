use super::*;

#[test]
fn domain_values_preserve_inclusive_byte_limits() {
    assert!(serde_json::from_str::<ConfigurationFormat>("\"bogus\"").is_err());
    for label in ["yaml", "toml", "json", "xml", "properties", "hocon"] {
        let value = serde_json::to_value(ConfigurationFormat::from_label(label).unwrap()).unwrap();
        assert_eq!(value, serde_json::json!(label));
        assert_eq!(
            serde_json::from_value::<ConfigurationFormat>(value)
                .unwrap()
                .label(),
            label
        );
    }
    for value in [" id", "id ", " id "] {
        assert_eq!(
            StableIdentifier::new(value),
            Err(DomainValidationError::InvalidIdentifier)
        );
    }
    // MAX_IDENTIFIER_BYTES and MAX_VERSION_BYTES are inclusive byte limits.
    for length in [127, 128, 129] {
        let value = "x".repeat(length);
        assert_eq!(StableIdentifier::new(value.clone()).is_ok(), length <= 128);
        assert_eq!(Version::new(value).is_ok(), length <= 128);
    }
    // MAX_PATH_BYTES is the inclusive authored-path limit.
    for length in [1024, 1025] {
        let value = "x".repeat(length);
        let evidence = EvaluationEvidence::new_with_optional(
            value.clone(),
            QueryDomain::code([Language::Rust]).unwrap(),
            None,
            None,
            None,
            None,
            [],
        );
        if length == 1024 {
            assert_eq!(
                serde_json::to_value(evidence.unwrap()).unwrap()["authored_path"],
                value
            );
        } else {
            assert_eq!(evidence, Err(DomainValidationError::InvalidAuthoredPath));
        }
    }
}

#[test]
fn heterogeneous_domains_check_cardinality_before_provenance_and_deduplicate() {
    let code = QueryDomain::code([Language::Rust]).unwrap();
    let config = QueryDomain::configuration([ConfigurationFormat::Json]).unwrap();
    let singleton = HeterogeneousRowDomain::new([code.clone()], DomainDiscriminator::Domain, false);
    assert_eq!(
        singleton.unwrap_err().to_string(),
        "heterogeneous rows require at least two distinct alternatives"
    );
    let distinct = HeterogeneousRowDomain::new(
        [code.clone(), config.clone()],
        DomainDiscriminator::Domain,
        true,
    )
    .unwrap();
    let repeated = HeterogeneousRowDomain::new(
        (0..9).flat_map(|_| [code.clone(), config.clone()]),
        DomainDiscriminator::Domain,
        true,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(repeated).unwrap(),
        serde_json::to_value(distinct).unwrap()
    );
}
