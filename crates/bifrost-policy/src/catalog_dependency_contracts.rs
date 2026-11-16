use crate::*;
use brokk_bifrost_test_macros::hardwon;

fn catalog_manifest(hash: &str) -> String {
    format!(
        r#"{{"schema_version":2,"id":"test.dependencies","version":"1.0.0","name":"Dependencies","description":"Test fixture","policies":[],"catalogs":[{{"path":"catalog.json","semantic_hash":"{hash}"}}]}}"#
    )
}

#[test]
fn embedded_catalog_requires_lowercase_content_identity() {
    let lower = "a".repeat(64);
    let catalog = BuiltInPolicyCatalog::from_embedded_packs(vec![EmbeddedPolicyPack::new(
        catalog_manifest(&lower),
    )]);
    assert_eq!(
        catalog.document().packs.len(),
        1,
        "{:?}",
        catalog.document()
    );
    assert!(catalog.document().rejected_packs.is_empty());
    let catalog = BuiltInPolicyCatalog::from_embedded_packs(vec![EmbeddedPolicyPack::new(
        catalog_manifest(&lower.to_uppercase()),
    )]);
    let [rejected] = catalog.document().rejected_packs.as_slice() else {
        panic!(
            "an uppercase pin rejects the pack: {:?}",
            catalog.document()
        );
    };
    assert_eq!(rejected.reason, PolicyPackRejection::InvalidManifest);
}

#[test]
fn embedded_inventory_rejects_unlisted_sources() {
    let catalog = BuiltInPolicyCatalog::from_embedded_packs(vec![
        EmbeddedPolicyPack::new(catalog_manifest(&"a".repeat(64)))
            .with_source("extra.rqlp", "unlisted"),
    ]);
    let [rejected] = catalog.document().rejected_packs.as_slice() else {
        panic!(
            "an unlisted source rejects the pack: {:?}",
            catalog.document()
        );
    };
    assert_eq!(rejected.reason, PolicyPackRejection::InvalidContent);
    assert!(rejected.message.contains("paths do not exactly match"));
}

#[test]
fn source_identity_preserves_final_newline() {
    assert_ne!(
        PolicySourceHash::from_source_bytes(b"policy"),
        PolicySourceHash::from_source_bytes(b"policy\n")
    );
}

#[test]
fn selection_exclusions_are_unique_and_deterministic() {
    let catalog = BuiltInPolicyCatalog::without_rules();
    let a = BuiltInPolicySelectionRecord::new(&catalog, &[], &["z".into(), "a".into(), "z".into()]);
    let b = BuiltInPolicySelectionRecord::new(&catalog, &[], &["a".into(), "z".into()]);
    assert_eq!(a, b);
}

#[test]
fn catalog_authored_identity_distinguishes_references() {
    let source = |name: &str| {
        format!(
            r#"(policy :id "test.catalog" :name "Catalog" :message (generated-message :relation can-reach) :severity warning :analysis (analysis :type taint :mode may :sources (endpoint-set :include-sets [(catalog :name "{name}" :version 1)]) :sinks (endpoint-set)))"#
        )
    };
    let identity = |text: String| {
        policy_source_identity(PolicySourceIdentity::new("test.rqlp"), text.as_bytes()).unwrap()
    };
    let a = identity(source("test.first"));
    let b = identity(source("test.second"));
    assert_ne!(a.authored_hash, b.authored_hash);
}

#[test]
fn flow_and_entry_point_sets_reject_direct_catalog_imports() {
    for (analysis, group) in [("flow", "origins"), ("taint", "entry-points")] {
        let empty = if analysis == "flow" {
            ":observations (endpoint-set)"
        } else {
            ":sources (endpoint-set) :sinks (endpoint-set)"
        };
        let source = format!(
            r#"(policy :id "test.catalog" :name "Catalog" :message (generated-message :relation can-reach) :severity warning :analysis (analysis :type {analysis} :mode may {empty} :{group} (endpoint-set :include-sets [(catalog :name "test.inputs" :version 1)])))"#
        );
        let error = parse_rqlp_source(&source, PolicySourceIdentity::new("test.rqlp")).unwrap_err();
        assert_eq!(error.diagnostic.code, "field-not-allowed");
        assert!(error.diagnostic.message.contains(":include-sets"));
    }
}

/// `bifrost.security.rust.cargo-ssh-git-host-key-unverified` as released in
/// bifrost-packs rules/v0.12.0 (pack `bifrost.security` 2.4.0), without its
/// leading comment block. CLI 0.15.1 authored the release, and its manifest
/// pins `authored_hash` and `resolved_semantic_hash` to
/// `RELEASED_CARGO_SSH_IDENTITY`.
const RELEASED_CARGO_SSH_POLICY: &str = r#"(policy
  :schema-version 1
  :id "bifrost.security.rust.cargo-ssh-git-host-key-unverified"
  :name "SSH git dependency fetched by a Cargo that skips host-key checks"
  :message "the pinned Rust toolchain predates 1.66.1, whose Cargo fetches this SSH git dependency without verifying the host key (CVE-2022-46176)"
  :severity warning
  :description "Reports a locked Cargo dependency with a git+ssh source in a package whose rust-toolchain file pins a Rust release before 1.66.1. Cargo's built-in git support in those releases does not verify the SSH host key, so a network attacker can serve the dependency. An unpinned toolchain, a missing Cargo.lock, or a workspace .cargo/config.toml leaves the run inconclusive. Ambient Cargo and git configuration is not read."
  :help-uri "https://blog.rust-lang.org/2023/01/10/cve-2022-46176/"
  :tags ["security" "rust" "cargo" "supply-chain" "cve-2022-46176" "cwe-322"]
  :analysis (analysis
    :type assertion
    (bind :name dependency
      :query (rql :schema-version 1
        (filter :where ((source regex "^git\\+ssh://"))
          (dependency-evidence :ecosystem cargo :kinds [locked]))))
    (bind :name toolchain
      :query (rql :schema-version 1
        (dependency-evidence :ecosystem rust-toolchain :version-range "<1.66.1")))
    (join :left dependency :right toolchain :on ((declared_by declared_by)))
    (group :name locked-ssh-dependency :by (dependency.id)
      (aggregate :name affected-toolchains :op count))
    (assert :group locked-ssh-dependency :value affected-toolchains :cardinality (exactly 0)))
  :classification (classification
    :fallback (classification-id :taxonomy "CWE" :id "322")))"#;
const RELEASED_CARGO_SSH_IDENTITY: &str =
    "6e27a37b6e1f966ab42e45a3b743fbcfdca585342a973a6f069d04fd3da69f6f";

#[hardwon("#11554: an empty lock-association axis moved a released policy's identity")]
#[test]
fn released_dependency_evidence_policy_keeps_its_pinned_identity() {
    let identity = |source: &str| {
        policy_source_identity(
            PolicySourceIdentity::new("bifrost.security.rust.cargo-ssh-git-host-key-unverified"),
            source.as_bytes(),
        )
        .unwrap()
    };
    let released = identity(RELEASED_CARGO_SSH_POLICY);
    assert_eq!(
        released.authored_hash.to_string(),
        RELEASED_CARGO_SSH_IDENTITY
    );
    match &released.analyzer_free {
        PolicySourceIdentityResolution::Available { semantic_hash } => {
            assert_eq!(semantic_hash.to_string(), RELEASED_CARGO_SSH_IDENTITY)
        }
        other => panic!("the released policy resolves without a workspace: {other:?}"),
    }

    // A query that uses the axis keeps it in its canonical form.
    let unconstrained = "(dependency-evidence :ecosystem cargo :kinds [locked])";
    assert_eq!(RELEASED_CARGO_SSH_POLICY.matches(unconstrained).count(), 1);
    let constrained = identity(&RELEASED_CARGO_SSH_POLICY.replace(
        unconstrained,
        "(dependency-evidence :ecosystem cargo :kinds [locked] :lock-association exact)",
    ));
    assert_ne!(constrained.authored_hash, released.authored_hash);
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10941: selecting a pack ID whose duplicate copy was rejected reported only a warning"
)]
fn a_selected_pack_id_with_a_rejected_duplicate_is_incomplete() {
    let manifest = |id: &str| {
        catalog_manifest(&"a".repeat(64)).replace("\"test.dependencies\"", &format!("\"{id}\""))
    };
    let catalog = BuiltInPolicyCatalog::from_embedded_packs(vec![
        EmbeddedPolicyPack::new(manifest("test.dependencies")),
        EmbeddedPolicyPack::new(manifest("test.other")),
        EmbeddedPolicyPack::new(manifest("test.dependencies")),
    ]);
    let [rejected] = catalog.document().rejected_packs.as_slice() else {
        panic!("the duplicate is rejected: {:?}", catalog.document());
    };
    assert_eq!(rejected.reason, PolicyPackRejection::Conflict);
    let notices = |packs: &[&str]| {
        catalog.rejection_notices(&BuiltInPolicySelection {
            packs: packs.iter().map(|pack| (*pack).to_owned()).collect(),
            ..BuiltInPolicySelection::default()
        })
    };
    // Naming the duplicated ID could have included the rejected copy.
    assert!(notices(&["test.dependencies"])[0].selection_incomplete);
    // Naming only another pack could not.
    assert!(!notices(&["test.other"])[0].selection_incomplete);
}
