use super::*;
use crate::finding_identity::{AdapterNamespaceError, AdapterOpaqueIdError, EvidenceRef};
use crate::finding_identity::{OpaqueFindingKey, SourceSliceHash, StableSemanticIdentityError};
use crate::future_evidence::TypestateFindingAnchor;
use brokk_bifrost_analysis::analyzer::canonical_hash::CanonicalHasher;

#[test]
fn declaration_identity_uses_its_producer_contract() {
    let declaration = format!("decl:v1:{}", "a".repeat(64));
    let identity =
        StableSemanticIdentity::analyzer_declaration_id("rust", path(), &declaration).unwrap();
    assert_eq!(identity.declaration_id(), Some(declaration.as_str()));
    assert_eq!(
        StableSemanticIdentity::analyzer_declaration_id("rust", path(), "arbitrary-key")
            .unwrap_err(),
        StableSemanticIdentityError::InvalidDeclarationId,
    );
}

#[test]
fn semantic_keys_reject_file_uris_and_hash_offsets_but_allow_empty_number_suffixes() {
    assert_eq!(
        StableSemanticIdentity::catalog_entry("rust", path(), "FILE:///tmp/source.rs").unwrap_err(),
        StableSemanticIdentityError::AbsoluteOrNativePathPrefix,
    );
    assert_eq!(
        StableSemanticIdentity::catalog_entry("rust", path(), "offset#12").unwrap_err(),
        StableSemanticIdentityError::CoordinateOrOffsetEncoding,
    );
    assert!(StableSemanticIdentity::catalog_entry("rust", path(), "line#").is_ok());
}

#[test]
fn typestate_finding_identity_is_scoped_to_its_policy() {
    let anchor = TypestateFindingAnchor::weak(
        OpaqueFindingKey::try_new("bifrost.test", "same-subject").unwrap(),
    );
    let first = PolicyId::new("security.first").unwrap();
    let second = PolicyId::new("security.second").unwrap();
    assert_ne!(
        PolicyFindingId::from_typestate_anchor(&first, &anchor),
        PolicyFindingId::from_typestate_anchor(&second, &anchor),
    );
}

#[test]
fn retained_report_cap_counts_strong_owner_namespace_and_declaration() {
    let loaded = loaded_match_policy();
    let default_budget = PolicyBudget::default();
    let declaration = format!("decl:v1:{}", "a".repeat(64));
    let namespace = "rust";
    let owner =
        StableSemanticIdentity::analyzer_declaration_id(namespace, path(), &declaration).unwrap();
    let make_finding = |owner: Option<StableSemanticIdentity>| {
        let anchor = MatchFindingAnchor::strong(
            MatchResultDomain::CallSite,
            path(),
            owner,
            Some(SourceSliceHash::from_bytes([4; 32])),
            0,
        )
        .unwrap();
        let evidence = PolicyFindingEvidence::Match {
            evidence: MatchFindingEvidence::try_new(
                MatchResultDomain::CallSite,
                anchor,
                call_terminal(),
                Vec::new(),
                false,
            )
            .unwrap(),
        };
        finding_with(&loaded, evidence, Vec::new(), None, &default_budget).unwrap()
    };
    let make_run = |finding: PolicyFinding, budget: &PolicyBudget| {
        PolicyRun::try_new(
            loaded.definition().metadata.id.clone(),
            loaded.semantic_hash(),
            PolicyAnalysisType::Match,
            PolicyRunCompletion::Complete,
            vec![finding],
            Vec::new(),
            false,
            PolicyWorkReport::default(),
            budget,
        )
    };
    let without_owner = make_run(make_finding(None), &default_budget).unwrap();
    let with_owner = make_finding(Some(owner));
    // The optional owner occupies inline storage in either case. Its three
    // owned strings are the only additional retained allocation.
    let exact_bytes =
        without_owner.retained_size() + namespace.len() + path().as_str().len() + declaration.len();
    let exact = PolicyBudget::builder()
        .with_max_retained_report_bytes(exact_bytes)
        .unwrap()
        .build()
        .unwrap();
    assert!(make_run(with_owner.clone(), &exact).is_ok());
    let below = PolicyBudget::builder()
        .with_max_retained_report_bytes(exact_bytes - 1)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(
        make_run(with_owner, &below).unwrap_err(),
        PolicyRunError::RetainedReportBytesExceeded {
            max: exact_bytes - 1
        },
    );
}

#[test]
fn opaque_ids_accept_the_exact_cap_and_keep_colons_in_the_payload() {
    let value = "x".repeat(256 - "adapter:".len());
    let exact = OpaqueFindingKey::try_new("adapter", &value).unwrap();
    assert_eq!(exact.as_str().len(), 256);
    assert_eq!(
        OpaqueFindingKey::try_new("adapter", format!("{value}x")).unwrap_err(),
        AdapterOpaqueIdError::TooLong { max_bytes: 256 },
    );
    let nested = OpaqueFindingKey::try_new("adapter", "part:tail").unwrap();
    let decoded: OpaqueFindingKey =
        serde_json::from_value(serde_json::to_value(&nested).unwrap()).unwrap();
    assert_eq!(decoded, nested);
    assert_eq!(decoded.as_str(), "adapter:part:tail");
}

#[test]
fn namespace_accepts_internal_underscores_but_requires_an_alphanumeric_end() {
    assert_eq!(
        OpaqueFindingKey::try_new("my_adapter", "value")
            .unwrap()
            .as_str(),
        "my_adapter:value",
    );
    assert_eq!(
        OpaqueFindingKey::try_new("my_adapter_", "value").unwrap_err(),
        AdapterOpaqueIdError::Namespace(AdapterNamespaceError::InvalidEnd),
    );
}

#[test]
fn semantic_and_declaration_encodings_enforce_their_boundaries() {
    let exact = "x".repeat(256);
    assert!(StableSemanticIdentity::catalog_entry("rust", path(), &exact).is_ok());
    assert_eq!(
        StableSemanticIdentity::catalog_entry("rust", path(), format!("{exact}x")).unwrap_err(),
        StableSemanticIdentityError::SemanticKeyTooLong { max_bytes: 256 },
    );
    let declaration = format!("decl:v1:{}", "a".repeat(64));
    assert!(StableSemanticIdentity::analyzer_declaration_id("rust", path(), &declaration).is_ok());
    assert_eq!(
        StableSemanticIdentity::analyzer_declaration_id(
            "rust",
            path(),
            format!("decl:v1:{}", "A".repeat(64)),
        )
        .unwrap_err(),
        StableSemanticIdentityError::InvalidDeclarationId,
    );
    assert!(
        StableSemanticIdentity::canonical_ast_identity(
            "rust",
            path(),
            r#"[["function_item",null]]"#,
        )
        .is_ok()
    );
    assert_eq!(
        StableSemanticIdentity::canonical_ast_identity(
            "rust", path(), r#"[["function_item",""]]"#,
        ).unwrap_err(),
        StableSemanticIdentityError::EmptySemanticKey,
    );
}

#[test]
fn reference_retention_reports_whether_it_removed_anything() {
    let a = EvidenceRef::try_new("test", "a").unwrap();
    let b = EvidenceRef::try_new("test", "b").unwrap();
    let mut refs = vec![a.clone(), b.clone()];
    assert!(!crate::finding_identity::retain_sorted_evidence_refs(
        &mut refs,
        &[a.clone(), b.clone()],
    ));
    assert_eq!(refs, vec![a.clone(), b]);
    assert!(crate::finding_identity::retain_sorted_evidence_refs(
        &mut refs,
        std::slice::from_ref(&a),
    ));
    assert_eq!(refs, vec![a]);
}

#[test]
fn match_vulnerability_digest_uses_its_domain_and_occurrence() {
    let typed_key = OpaqueFindingKey::try_new("test", "same-site").unwrap();
    let weak = MatchFindingAnchor::weak(MatchResultDomain::CallSite, path(), typed_key.clone());
    let digest = crate::finding_identity::match_vulnerability_digest(&weak);
    assert_eq!(
        digest,
        crate::finding_identity::match_vulnerability_digest(&weak)
    );

    // The persisted vulnerability domain and analysis kind are part of the
    // identity contract. Build the reference from the shared canonical hash
    // primitive, independently of the policy digest helper under test.
    let reference = |domain: &[u8], analysis: &[u8]| {
        let mut hash = CanonicalHasher::new(domain);
        for field in [
            analysis,
            b"weak".as_slice(),
            b"call_site".as_slice(),
            path().as_str().as_bytes(),
            typed_key.as_str().as_bytes(),
        ] {
            hash.value(field);
        }
        hash.finish()
    };
    assert_eq!(
        digest,
        reference(b"bifrost-policy-vulnerability/v1", b"match")
    );
    assert_ne!(
        digest,
        reference(b"bifrost-policy-vulnerability/v1", b"assertion")
    );
    assert_ne!(digest, reference(b"bifrost-policy-finding/v1", b"match"));

    let strong = |ordinal| {
        MatchFindingAnchor::strong(
            MatchResultDomain::CallSite,
            path(),
            None,
            Some(SourceSliceHash::from_bytes([7; 32])),
            ordinal,
        )
        .unwrap()
    };
    let first = strong(0);
    let second = strong(1);
    assert_eq!(
        crate::finding_identity::match_vulnerability_digest(&first),
        crate::finding_identity::match_vulnerability_digest(&first),
    );
    assert_ne!(
        crate::finding_identity::match_vulnerability_digest(&first),
        crate::finding_identity::match_vulnerability_digest(&second),
    );
}
