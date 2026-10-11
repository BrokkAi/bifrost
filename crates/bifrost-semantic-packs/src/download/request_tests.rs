use super::test_support::*;
use super::*;
use jsonschema::{Registry, Validator};
use std::path::Path;
use tempfile::tempdir;

const PRIVATE_REPOSITORY: &str = "https://github.com/example/private-packs";
const TEST_TOKEN: &str = "fixture-secret-token-4741";
const RESPONSE_BODY_MARKER: &str = "fixture-response-body-must-not-leak";

fn preferred_request(pack_id: &str, repository: &str) -> PackRequest {
    PackRequest {
        request_schema_version: 1,
        pack_id: pack_id.to_owned(),
        repository: repository.to_owned(),
        inventory: None,
        selection: PackSelection::Preferred {
            preferred_version: None,
            allowed_versions: "*".to_owned(),
            channel: PackChannel::Stable,
        },
        dependencies: Vec::new(),
    }
}

fn request_with_selection(
    pack_id: &str,
    repository: &str,
    selection: PackSelection,
    dependencies: Vec<PackDependencyPin>,
) -> PackRequest {
    PackRequest {
        request_schema_version: 1,
        pack_id: pack_id.to_owned(),
        repository: repository.to_owned(),
        inventory: None,
        selection,
        dependencies,
    }
}

fn policy_release(
    releases: &mut Vec<Value>,
    responses: &mut BTreeMap<String, Vec<u8>>,
    repository: &str,
    version: &str,
    policy_bytes: &[u8],
    dependencies: Vec<Value>,
) -> String {
    policy_release_with_tag_override(
        releases,
        responses,
        repository,
        version,
        policy_bytes,
        dependencies,
        None,
    )
}

fn policy_release_with_tag_override(
    releases: &mut Vec<Value>,
    responses: &mut BTreeMap<String, Vec<u8>>,
    repository: &str,
    version: &str,
    policy_bytes: &[u8],
    dependencies: Vec<Value>,
    tag_override: Option<&str>,
) -> String {
    let path = "rules/fixture/policy.rql";
    let archive = test_archive(&[(path, policy_bytes)]);
    add_release_for_with_tag_override(
        releases,
        responses,
        ReleaseFixture {
            pack_id: RULES_PACK_ID,
            version,
            schema_version: 2,
            artifact_role: "policy",
            archive: &archive,
            contents: vec![content_entry("policy", version, path, policy_bytes)],
            dependencies,
        },
        repository,
        tag_override,
    )
}

fn native_dependency_release(
    releases: &mut Vec<Value>,
    responses: &mut BTreeMap<String, Vec<u8>>,
    repository: &str,
    version: &str,
) -> String {
    let path = "bifrost-semantic-packs/index.json";
    let bytes = b"{\"packs\":[]}";
    let archive = test_archive(&[(path, bytes)]);
    add_release_for(
        releases,
        responses,
        ReleaseFixture {
            pack_id: SEMANTIC_PACK_ID,
            version,
            schema_version: 2,
            artifact_role: "native",
            archive: &archive,
            contents: vec![content_entry("semantic-model", version, path, bytes)],
            dependencies: Vec::new(),
        },
        repository,
    )
}

fn dependency_root_manifest(version: &str, repository: &str) -> Value {
    json!([{
        "pack_id": SEMANTIC_PACK_ID,
        "release_version": version,
        "repository": repository,
    }])
}

fn dependency_request_pin(version: Option<&str>, digest: &str) -> PackDependencyPin {
    PackDependencyPin {
        pack_id: SEMANTIC_PACK_ID.to_owned(),
        repository: REPOSITORY_URL.to_owned(),
        release_version: version.map(str::to_owned),
        manifest_sha256: digest.to_owned(),
    }
}

fn profile_value(profile: &EngineProfile) -> Value {
    serde_json::to_value(profile).expect("serialize fixture engine profile")
}

fn complete_outcome(
    profile: &EngineProfile,
    request: Option<&PackRequest>,
    result: Result<OpenPackSelection, OpenPackError>,
) -> Value {
    let mut outcome = acquisition_outcome(&profile_value(profile), request, result);
    outcome["engine"]["executable_sha256"] = json!("e".repeat(64));
    outcome
}

fn prepare_outcome(
    cache: &Path,
    profile: &EngineProfile,
    request: &PackRequest,
    offline: bool,
    refresh: bool,
    transport: &dyn HttpTransport,
) -> Value {
    complete_outcome(
        profile,
        Some(request),
        prepare_result(cache, profile, request, offline, refresh, transport),
    )
}

fn prepare_result(
    cache: &Path,
    profile: &EngineProfile,
    request: &PackRequest,
    offline: bool,
    refresh: bool,
    transport: &dyn HttpTransport,
) -> Result<OpenPackSelection, OpenPackError> {
    let source = request_source(request);
    prepare_with_request(
        cache,
        profile,
        request,
        offline,
        refresh,
        Some(&source),
        transport,
    )
}

fn outcome_for_request_error(profile: &EngineProfile, error: OpenPackError) -> Value {
    complete_outcome(profile, None, Err(error))
}

fn normalize_outcome(mut outcome: Value, cache: &Path) -> Value {
    fn normalize(value: &mut Value, cache_root: &str) {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    if matches!(key.as_str(), "created_at" | "fetched_at") {
                        *value = json!("<TIMESTAMP>");
                    } else {
                        normalize(value, cache_root);
                    }
                }
            }
            Value::Array(values) => {
                for value in values {
                    normalize(value, cache_root);
                }
            }
            Value::String(value) => {
                *value = value.replace(cache_root, "<CACHE>");
            }
            _ => {}
        }
    }

    normalize(&mut outcome, &cache.to_string_lossy());
    outcome
}

fn assert_golden(name: &str, outcome: Value, cache: &Path) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/acquisition")
        .join(name)
        .join("expected.json");
    let actual = render_canonical_outcome(&normalize_outcome(outcome, cache));
    if std::env::var("BIFROST_BLESS").as_deref() == Ok("1") {
        fs::create_dir_all(path.parent().expect("golden fixture parent"))
            .expect("create acquisition golden directory");
        fs::write(path, actual).expect("write acquisition golden outcome");
        return;
    }
    let expected = fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "read golden fixture {}: {error}; run with BIFROST_BLESS=1",
            path.display()
        )
    });
    let expected = serde_json::from_slice::<Value>(&expected)
        .unwrap_or_else(|error| panic!("parse golden fixture {}: {error}", path.display()));
    let expected = render_canonical_outcome(&expected);
    assert_eq!(
        String::from_utf8_lossy(&actual),
        String::from_utf8_lossy(&expected),
        "acquisition outcome differs from {}",
        path.display()
    );
}

/// Renders an acquisition outcome for golden comparison with object keys sorted
/// recursively. `serde_json`'s `preserve_order` feature is unified across a
/// workspace build, so without this the outcome would serialize in `json!`
/// insertion order while the fixtures are sorted alphabetically.
fn render_canonical_outcome(outcome: &Value) -> Vec<u8> {
    let mut rendered = serde_json::to_vec_pretty(&sorted_json_value(outcome))
        .expect("serialize canonical golden outcome");
    rendered.push(b'\n');
    rendered
}

fn request_schema_validators() -> (Validator, Validator, Validator) {
    let schema_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas");
    let request = serde_json::from_slice::<Value>(
        &fs::read(schema_dir.join("pack-request-v1.schema.json")).expect("read request schema"),
    )
    .expect("parse request schema");
    let receipt = serde_json::from_slice::<Value>(
        &fs::read(schema_dir.join("pack-selection-receipt-v3.schema.json"))
            .expect("read receipt schema"),
    )
    .expect("parse receipt schema");
    let outcome = serde_json::from_slice::<Value>(
        &fs::read(schema_dir.join("pack-acquisition-outcome-v1.schema.json"))
            .expect("read outcome schema"),
    )
    .expect("parse outcome schema");
    let registry = Registry::new()
        .add(
            "https://bifrost.dev/schemas/pack-request-v1.schema.json",
            request.clone(),
        )
        .expect("register request schema")
        .add(
            "https://bifrost.dev/schemas/pack-selection-receipt-v3.schema.json",
            receipt.clone(),
        )
        .expect("register receipt schema")
        .add(
            "https://bifrost.dev/schemas/pack-acquisition-outcome-v1.schema.json",
            outcome.clone(),
        )
        .expect("register outcome schema")
        .prepare()
        .expect("prepare schema registry");
    let request_validator = jsonschema::options()
        .with_registry(&registry)
        .build(&request)
        .expect("compile request schema");
    let receipt_validator = jsonschema::options()
        .with_registry(&registry)
        .build(&receipt)
        .expect("compile receipt schema");
    let outcome_validator = jsonschema::options()
        .with_registry(&registry)
        .build(&outcome)
        .expect("compile outcome schema");
    (request_validator, receipt_validator, outcome_validator)
}

#[test]
fn strict_request_selects_the_listed_release_by_version_and_manifest_digest() {
    let cache = tempdir().expect("temporary strict-selection cache");
    let first_bytes = b"first policy";
    let selected_bytes = b"selected policy";
    let first_archive = test_archive(&[("rules/fixture/policy.rql", first_bytes)]);
    let selected_archive = test_archive(&[("rules/fixture/policy.rql", selected_bytes)]);
    let mut releases = Vec::new();
    let mut responses = BTreeMap::new();
    add_release(
        &mut releases,
        &mut responses,
        ReleaseFixture {
            pack_id: RULES_PACK_ID,
            version: "1.0.0",
            schema_version: 2,
            artifact_role: "policy",
            archive: &first_archive,
            contents: vec![content_entry(
                "policy",
                "first",
                "rules/fixture/policy.rql",
                first_bytes,
            )],
            dependencies: Vec::new(),
        },
    );
    let selected_digest = add_release_for(
        &mut releases,
        &mut responses,
        ReleaseFixture {
            pack_id: RULES_PACK_ID,
            version: "1.2.0",
            schema_version: 2,
            artifact_role: "policy",
            archive: &selected_archive,
            contents: vec![content_entry(
                "policy",
                "selected",
                "rules/fixture/policy.rql",
                selected_bytes,
            )],
            dependencies: Vec::new(),
        },
        REPOSITORY_URL,
    );
    let transport = FakeTransport::new(responses);
    let request = PackRequest {
        request_schema_version: 1,
        pack_id: RULES_PACK_ID.to_owned(),
        repository: REPOSITORY_URL.to_owned(),
        inventory: None,
        selection: PackSelection::Strict {
            release_version: "1.2.0".to_owned(),
            manifest_sha256: selected_digest,
        },
        dependencies: Vec::new(),
    };
    let source = request_source(&request);
    let selected = prepare_with_request(
        cache.path(),
        &engine_profile("9.9.0"),
        &request,
        false,
        false,
        Some(&source),
        &transport,
    )
    .expect("strict request selects exact listed release");
    let receipt: Value = serde_json::from_slice(
        &fs::read(&selected.receipt_path).expect("read strict selection receipt"),
    )
    .expect("parse strict selection receipt");
    assert_eq!(receipt["selection_reason"], "strict-lock");
    assert_eq!(receipt["releases"][0]["release_version"], "1.2.0");

    let mut wrong_digest = request;
    let PackSelection::Strict {
        manifest_sha256, ..
    } = &mut wrong_digest.selection
    else {
        unreachable!("test request is strict")
    };
    *manifest_sha256 = "a".repeat(64);
    let offline_transport = FakeTransport::new(BTreeMap::new());
    let error = prepare_with_request(
        cache.path(),
        &engine_profile("9.9.0"),
        &wrong_digest,
        true,
        false,
        Some(&source),
        &offline_transport,
    )
    .expect_err("strict digest mismatch is an integrity failure");
    assert!(matches!(error, OpenPackError::Integrity(_)));
    assert_eq!(offline_transport.call_count(), 0);
}

#[test]
fn private_repository_release_listing_404_is_access_denied() {
    let cache = tempdir().expect("temporary private-source cache");
    let repository = "https://github.com/example/private-packs";
    let url = "https://api.github.com/repos/example/private-packs/releases?per_page=100&page=1";
    let transport = FakeTransport::with_failures(BTreeMap::from([(
        url.to_owned(),
        TransportError::http_status(404, true, &ureq::http::HeaderMap::new()),
    )]));
    let request = preferred_request("bifrost.premium", repository);
    let source = request_source(&request);
    let error = prepare_with_request(
        cache.path(),
        &engine_profile("9.9.0"),
        &request,
        false,
        false,
        Some(&source),
        &transport,
    )
    .expect_err("private listing 404 is not an empty inventory");
    assert!(matches!(error, OpenPackError::Authentication(_)));
    assert_eq!(error.failure_class().name, "access-denied");
    assert_eq!(transport.call_count(), 1);
}

#[test]
fn zip_extraction_rejects_unsafe_paths_and_symbolic_links() {
    let cache = tempdir().expect("temporary ZIP safety directory");
    let unsafe_path = test_zip_archive(&[("../outside", b"escape")]);
    let unsafe_path_file = cache.path().join("unsafe-path.zip");
    fs::write(&unsafe_path_file, unsafe_path).expect("write unsafe-path ZIP");
    assert!(matches!(
        inspect_zip_archive(&unsafe_path_file, None),
        Err(OpenPackError::Integrity(_))
    ));

    let symlink_archive = test_zip_symlink_archive("rules/link", b"target");
    let symlink_file = cache.path().join("symlink.zip");
    fs::write(&symlink_file, symlink_archive).expect("write symlink ZIP");
    assert!(matches!(
        inspect_zip_archive(&symlink_file, None),
        Err(OpenPackError::Integrity(_))
    ));
}

#[test]
fn premium_policy_zip_is_selected_and_receipt_request_replays_offline() {
    let repository = "https://github.com/example/private-packs";
    let premium_cache = tempdir().expect("temporary premium cache");
    let mut releases = Vec::new();
    let mut responses = BTreeMap::new();
    add_premium_release(&mut releases, &mut responses, repository);
    let transport = FakeTransport::new(responses);
    let request = preferred_request("bifrost.premium", repository);
    let source = request_source(&request);
    let incompatible = prepare_with_request(
        premium_cache.path(),
        &engine_profile("9.9.0"),
        &request,
        false,
        false,
        Some(&source),
        &transport,
    )
    .expect_err("premium release requires its declared engine contract");
    assert!(incompatible.is_no_compatible_release());
    let incompatible_outcome = acquisition_outcome(
        &serde_json::to_value(engine_profile("9.9.0")).expect("serialize profile"),
        None,
        Err(incompatible),
    );
    assert_eq!(
        incompatible_outcome["failure"]["class"],
        "no-compatible-release"
    );
    assert_eq!(
        incompatible_outcome["rejections"][0]["reason"],
        "engine-contract"
    );
    let detail = incompatible_outcome["rejections"][0]["detail"]
        .as_str()
        .expect("engine incompatibility detail");
    for capability in [
        "actual-to-formal-binding",
        "exact-call-target",
        "flow",
        "taint",
        "policy_bundle",
    ] {
        assert!(
            detail.contains(capability),
            "missing {capability} from {detail}"
        );
    }

    let mut profile = engine_profile("9.9.0");
    profile.schemas.policy_bundle = vec![1];
    profile.capabilities = vec![
        "actual-to-formal-binding".to_owned(),
        "exact-call-target".to_owned(),
        "flow".to_owned(),
        "taint".to_owned(),
    ];
    let selected = prepare_with_request(
        premium_cache.path(),
        &profile,
        &request,
        false,
        false,
        Some(&source),
        &transport,
    )
    .expect("premium policy ZIP is compatible with the engine");
    assert!(
        selected
            .policy_pack_root
            .join("compiled/java/premium.rqlp")
            .is_file()
    );
    assert!(selected.semantic_bundle_root.is_none());
    let receipt: Value =
        serde_json::from_slice(&fs::read(&selected.receipt_path).expect("read premium receipt"))
            .expect("parse premium receipt");
    assert_eq!(receipt["status"], "compatible");
    assert_eq!(receipt["releases"][0]["visibility"], "private");
    assert_eq!(receipt["releases"][0]["tag"], "v0.3.0");

    let replay_bytes = serde_json::to_vec(&receipt["replay"]).expect("serialize receipt replay");
    let replay = parse_pack_request(&replay_bytes).expect("validate receipt replay request");
    let offline = FakeTransport::new(BTreeMap::new());
    let replayed = prepare_with_request(
        premium_cache.path(),
        &profile,
        &replay,
        true,
        false,
        Some(&source),
        &offline,
    )
    .expect("receipt replay uses the verified offline cache");
    assert_eq!(replayed.selection_id, selected.selection_id);
    assert!(replayed.cache_reused);
    assert_eq!(offline.call_count(), 0);
}

#[test]
fn acquisition_roots_and_dependency_pins_match_golden_outcomes() {
    let cache = tempdir().expect("temporary public-root cache");
    let mut releases = Vec::new();
    let mut responses = BTreeMap::new();
    policy_release(
        &mut releases,
        &mut responses,
        REPOSITORY_URL,
        "1.0.0",
        b"public policy",
        Vec::new(),
    );
    let request = default_preferred_request();
    let transport = FakeTransport::new(responses);
    let outcome = prepare_outcome(
        cache.path(),
        &engine_profile("9.9.0"),
        &request,
        false,
        false,
        &transport,
    );
    assert_eq!(outcome["status"], "selected");
    assert_golden("public-default-preferences", outcome, cache.path());

    let cache = tempdir().expect("temporary compatible premium cache");
    let mut releases = Vec::new();
    let mut responses = BTreeMap::new();
    add_premium_release(&mut releases, &mut responses, PRIVATE_REPOSITORY);
    let request = preferred_request("bifrost.premium", PRIVATE_REPOSITORY);
    let transport = FakeTransport::new(responses);
    let outcome = prepare_outcome(
        cache.path(),
        &premium_engine_profile(),
        &request,
        false,
        false,
        &transport,
    );
    assert_eq!(outcome["status"], "selected");
    assert_eq!(
        outcome["selection"]["receipt"]["releases"][0]["visibility"],
        "private"
    );
    assert!(outcome["selection"]["semantic_bundle_root"].is_null());
    assert_golden("premium-private-policy-zip", outcome, cache.path());

    let cache = tempdir().expect("temporary incompatible premium cache");
    let mut releases = Vec::new();
    let mut responses = BTreeMap::new();
    add_premium_release(&mut releases, &mut responses, PRIVATE_REPOSITORY);
    let request = preferred_request("bifrost.premium", PRIVATE_REPOSITORY);
    let transport = FakeTransport::new(responses);
    let outcome = prepare_outcome(
        cache.path(),
        &engine_profile("9.9.0"),
        &request,
        false,
        false,
        &transport,
    );
    assert_eq!(outcome["failure"]["class"], "no-compatible-release");
    let detail = outcome["rejections"][0]["detail"]
        .as_str()
        .expect("premium contract rejection detail");
    for missing in [
        "actual-to-formal-binding",
        "exact-call-target",
        "flow",
        "taint",
        "policy_bundle",
    ] {
        assert!(detail.contains(missing), "{missing} missing from {detail}");
    }
    assert_golden(
        "premium-incompatible-current-profile",
        outcome,
        cache.path(),
    );

    for (name, mode, wrong_pin) in [
        ("preferred-correct-dependency-pin", "preferred", "none"),
        ("preferred-wrong-dependency-digest", "preferred", "digest"),
        ("preferred-wrong-dependency-version", "preferred", "version"),
        ("strict-correct-dependency-pin", "strict", "none"),
        ("strict-wrong-dependency-digest", "strict", "digest"),
        ("strict-wrong-dependency-version", "strict", "version"),
    ] {
        let cache = tempdir().expect("temporary dependency cache");
        let mut releases = Vec::new();
        let mut responses = BTreeMap::new();
        let dependency_digest =
            native_dependency_release(&mut releases, &mut responses, REPOSITORY_URL, "1.0.0");
        let root_digest = policy_release(
            &mut releases,
            &mut responses,
            REPOSITORY_URL,
            "1.0.0",
            b"dependency-bearing policy",
            dependency_root_manifest("1.0.0", REPOSITORY_URL)
                .as_array()
                .expect("one root dependency")
                .clone(),
        );
        let pin_digest = if wrong_pin == "digest" {
            "0".repeat(64)
        } else {
            dependency_digest
        };
        let pin_version = if wrong_pin == "version" {
            Some("1.1.0")
        } else {
            Some("1.0.0")
        };
        let dependency_pins = vec![dependency_request_pin(pin_version, &pin_digest)];
        let selection = if mode == "strict" {
            PackSelection::Strict {
                release_version: "1.0.0".to_owned(),
                manifest_sha256: root_digest,
            }
        } else {
            PackSelection::Preferred {
                preferred_version: Some("1.0.0".to_owned()),
                allowed_versions: "*".to_owned(),
                channel: PackChannel::Stable,
            }
        };
        let request =
            request_with_selection(RULES_PACK_ID, REPOSITORY_URL, selection, dependency_pins);
        let transport = FakeTransport::new(responses);
        let outcome = prepare_outcome(
            cache.path(),
            &engine_profile("9.9.0"),
            &request,
            false,
            false,
            &transport,
        );
        if wrong_pin == "none" {
            assert_eq!(outcome["status"], "selected", "{name}: {outcome}");
        } else {
            assert_eq!(
                outcome["rejections"][0]["reason"], "dependency-pin-mismatch",
                "{name}"
            );
            let expected_class = if mode == "strict" && wrong_pin == "digest" {
                "integrity"
            } else if mode == "strict" {
                "incompatible-strict-selection"
            } else {
                "no-compatible-release"
            };
            assert_eq!(outcome["failure"]["class"], expected_class, "{name}");
        }
        assert_golden(name, outcome, cache.path());
    }
}

#[test]
fn acquisition_preference_range_channel_and_strict_outcomes_match_goldens() {
    {
        let cache = tempdir().expect("temporary matching-preference cache");
        let mut releases = Vec::new();
        let mut responses = BTreeMap::new();
        policy_release(
            &mut releases,
            &mut responses,
            REPOSITORY_URL,
            "1.0.0",
            b"one",
            Vec::new(),
        );
        policy_release(
            &mut releases,
            &mut responses,
            REPOSITORY_URL,
            "2.0.0",
            b"two",
            Vec::new(),
        );
        let request = request_with_selection(
            RULES_PACK_ID,
            REPOSITORY_URL,
            PackSelection::Preferred {
                preferred_version: Some("1.0.0".to_owned()),
                allowed_versions: "*".to_owned(),
                channel: PackChannel::Stable,
            },
            Vec::new(),
        );
        let outcome = prepare_outcome(
            cache.path(),
            &engine_profile("9.9.0"),
            &request,
            false,
            false,
            &FakeTransport::new(responses),
        );
        assert_eq!(
            outcome["selection"]["receipt"]["selection_reason"],
            "preferred-version"
        );
        assert_golden("matching-preferred-version", outcome, cache.path());
    }

    {
        let cache = tempdir().expect("temporary stale-preference cache");
        let mut releases = Vec::new();
        let mut responses = BTreeMap::new();
        policy_release(
            &mut releases,
            &mut responses,
            REPOSITORY_URL,
            "1.0.0",
            b"old",
            Vec::new(),
        );
        mutate_release_manifest(
            &mut responses,
            REPOSITORY_URL,
            "rules/v1.0.0",
            None,
            |manifest| {
                manifest["compatibility"]["capabilities"]["required"] =
                    json!(["capability.missing-from-profile"]);
            },
        );
        policy_release(
            &mut releases,
            &mut responses,
            REPOSITORY_URL,
            "1.1.0",
            b"new",
            Vec::new(),
        );
        let request = request_with_selection(
            RULES_PACK_ID,
            REPOSITORY_URL,
            PackSelection::Preferred {
                preferred_version: Some("1.0.0".to_owned()),
                allowed_versions: "*".to_owned(),
                channel: PackChannel::Stable,
            },
            Vec::new(),
        );
        let outcome = prepare_outcome(
            cache.path(),
            &engine_profile("9.9.0"),
            &request,
            false,
            false,
            &FakeTransport::new(responses),
        );
        assert_eq!(
            outcome["selection"]["receipt"]["selection_reason"],
            "highest-eligible"
        );
        assert_eq!(
            outcome["selection"]["receipt"]["rejections"][0]["release_version"],
            "1.0.0"
        );
        assert_golden(
            "stale-preferred-incompatible-higher-alternative",
            outcome,
            cache.path(),
        );
    }

    for (name, versions, allowed, expected_version) in [
        (
            "range-lower-inclusive",
            vec!["0.9.9", "1.0.0"],
            ">=1.0.0, <2.0.0",
            "1.0.0",
        ),
        (
            "range-upper-exclusive",
            vec!["1.9.9", "2.0.0"],
            ">=1.0.0, <2.0.0",
            "1.9.9",
        ),
    ] {
        let cache = tempdir().expect("temporary range-boundary cache");
        let mut releases = Vec::new();
        let mut responses = BTreeMap::new();
        for version in versions {
            policy_release(
                &mut releases,
                &mut responses,
                REPOSITORY_URL,
                version,
                version.as_bytes(),
                Vec::new(),
            );
        }
        let request = request_with_selection(
            RULES_PACK_ID,
            REPOSITORY_URL,
            PackSelection::Preferred {
                preferred_version: None,
                allowed_versions: allowed.to_owned(),
                channel: PackChannel::Stable,
            },
            Vec::new(),
        );
        let outcome = prepare_outcome(
            cache.path(),
            &engine_profile("9.9.0"),
            &request,
            false,
            false,
            &FakeTransport::new(responses),
        );
        assert_eq!(
            outcome["selection"]["receipt"]["releases"][0]["release_version"],
            expected_version
        );
        assert_golden(name, outcome, cache.path());
    }

    for (name, channel) in [
        ("stable-channel-excludes-prerelease", PackChannel::Stable),
        (
            "prerelease-channel-admits-prerelease",
            PackChannel::Prerelease,
        ),
    ] {
        let cache = tempdir().expect("temporary channel cache");
        let mut releases = Vec::new();
        let mut responses = BTreeMap::new();
        policy_release(
            &mut releases,
            &mut responses,
            REPOSITORY_URL,
            "1.0.0",
            b"stable",
            Vec::new(),
        );
        policy_release(
            &mut releases,
            &mut responses,
            REPOSITORY_URL,
            "1.1.0-rc.1",
            b"preview",
            Vec::new(),
        );
        mutate_release_manifest(
            &mut responses,
            REPOSITORY_URL,
            "rules/v1.1.0-rc.1",
            Some(true),
            |_| {},
        );
        let request = request_with_selection(
            RULES_PACK_ID,
            REPOSITORY_URL,
            PackSelection::Preferred {
                preferred_version: None,
                allowed_versions: if channel == PackChannel::Prerelease {
                    ">=1.1.0-0".to_owned()
                } else {
                    "*".to_owned()
                },
                channel,
            },
            Vec::new(),
        );
        let outcome = prepare_outcome(
            cache.path(),
            &engine_profile("9.9.0"),
            &request,
            false,
            false,
            &FakeTransport::new(responses),
        );
        if channel == PackChannel::Stable {
            assert_eq!(
                outcome["selection"]["receipt"]["releases"][0]["release_version"],
                "1.0.0"
            );
            assert_eq!(outcome["rejections"][0]["reason"], "channel");
        } else {
            assert_eq!(
                outcome["selection"]["receipt"]["releases"][0]["release_version"], "1.1.0-rc.1",
                "{name}: {outcome}"
            );
        }
        assert_golden(name, outcome, cache.path());
    }

    {
        let cache = tempdir().expect("temporary strict-missing cache");
        let mut releases = Vec::new();
        let mut responses = BTreeMap::new();
        policy_release(
            &mut releases,
            &mut responses,
            REPOSITORY_URL,
            "2.0.0",
            b"tempting",
            Vec::new(),
        );
        let request = request_with_selection(
            RULES_PACK_ID,
            REPOSITORY_URL,
            PackSelection::Strict {
                release_version: "1.0.0".to_owned(),
                manifest_sha256: "a".repeat(64),
            },
            Vec::new(),
        );
        let outcome = prepare_outcome(
            cache.path(),
            &engine_profile("9.9.0"),
            &request,
            false,
            false,
            &FakeTransport::new(responses),
        );
        assert_eq!(outcome["failure"]["class"], "missing-strict-selection");
        assert!(outcome["selection"].is_null());
        assert_golden(
            "strict-missing-with-higher-alternative",
            outcome,
            cache.path(),
        );
    }

    {
        let cache = tempdir().expect("temporary strict-incompatible cache");
        let mut releases = Vec::new();
        let mut responses = BTreeMap::new();
        let pinned_digest = policy_release(
            &mut releases,
            &mut responses,
            REPOSITORY_URL,
            "1.0.0",
            b"pinned",
            Vec::new(),
        );
        mutate_release_manifest(
            &mut responses,
            REPOSITORY_URL,
            "rules/v1.0.0",
            None,
            |manifest| {
                manifest["compatibility"]["capabilities"]["required"] =
                    json!(["capability.strict-pin-cannot-use-alternative"]);
            },
        );
        policy_release(
            &mut releases,
            &mut responses,
            REPOSITORY_URL,
            "2.0.0",
            b"tempting",
            Vec::new(),
        );
        let updated_digest = {
            let listing = serde_json::from_slice::<Vec<Value>>(
                responses
                    .get(&release_listing_url(REPOSITORY_URL))
                    .expect("listing"),
            )
            .expect("parse listing");
            let descriptor = listing[0]["assets"]
                .as_array()
                .expect("assets")
                .iter()
                .find(|asset| asset["name"] == "pack-release.json")
                .expect("descriptor");
            let bytes = responses
                .get(descriptor["browser_download_url"].as_str().expect("URL"))
                .expect("descriptor bytes");
            sha256(bytes)
        };
        assert_ne!(pinned_digest, updated_digest);
        let request = request_with_selection(
            RULES_PACK_ID,
            REPOSITORY_URL,
            PackSelection::Strict {
                release_version: "1.0.0".to_owned(),
                manifest_sha256: updated_digest,
            },
            Vec::new(),
        );
        let outcome = prepare_outcome(
            cache.path(),
            &engine_profile("9.9.0"),
            &request,
            false,
            false,
            &FakeTransport::new(responses),
        );
        assert_eq!(outcome["failure"]["class"], "incompatible-strict-selection");
        assert_eq!(outcome["rejections"][0]["release_version"], "1.0.0");
        assert_golden(
            "strict-incompatible-with-higher-alternative",
            outcome,
            cache.path(),
        );
    }
}

#[test]
fn acquisition_compatibility_and_qualification_outcomes_match_goldens() {
    for (name, defect) in [
        ("missing-root-capability", "top-level-capability"),
        ("missing-content-capability", "content-capability"),
        ("incompatible-schema-axis", "schema-axis"),
    ] {
        let cache = tempdir().expect("temporary engine-contract cache");
        let mut releases = Vec::new();
        let mut responses = BTreeMap::new();
        policy_release(
            &mut releases,
            &mut responses,
            REPOSITORY_URL,
            "1.0.0",
            b"contract",
            Vec::new(),
        );
        mutate_release_manifest(
            &mut responses,
            REPOSITORY_URL,
            "rules/v1.0.0",
            None,
            |manifest| match defect {
                "top-level-capability" => {
                    manifest["compatibility"]["capabilities"]["required"] =
                        json!(["capability.root-required"]);
                }
                "content-capability" => {
                    manifest["compatibility"]["capabilities"]["required"] =
                        json!(["capability.content-required"]);
                    manifest["contents"][0]["required_capabilities"] =
                        json!(["capability.content-required"]);
                }
                "schema-axis" => {
                    manifest["compatibility"]["schemas"]["policy_bundle"] = json!([7]);
                    manifest["contents"][0]["schemas"]["policy_bundle"] = json!([7]);
                }
                _ => unreachable!("known engine-contract scenario"),
            },
        );
        let request = default_preferred_request();
        let outcome = prepare_outcome(
            cache.path(),
            &engine_profile("9.9.0"),
            &request,
            false,
            false,
            &FakeTransport::new(responses),
        );
        assert_eq!(
            outcome["failure"]["class"], "no-compatible-release",
            "{name}"
        );
        assert_eq!(
            outcome["rejections"][0]["reason"], "engine-contract",
            "{name}"
        );
        assert_golden(name, outcome, cache.path());
    }

    for (name, qualification, expected_class) in [
        (
            "root-pending-qualification",
            json!({
                "integrity": { "status": "pending", "evidence": [] },
                "behavior": { "status": "qualified", "evidence": ["fixture behavior"] },
            }),
            "pending",
        ),
        (
            "root-integrity-qualification-failed",
            json!({
                "integrity": { "status": "failed", "evidence": ["fixture integrity failed"] },
                "behavior": { "status": "qualified", "evidence": ["fixture behavior"] },
            }),
            "integrity",
        ),
        (
            "root-behavior-qualification-failed",
            json!({
                "integrity": { "status": "verified", "evidence": ["fixture integrity"] },
                "behavior": { "status": "failed", "evidence": ["fixture behavior failed"] },
            }),
            "unqualified",
        ),
    ] {
        let cache = tempdir().expect("temporary root-qualification cache");
        let mut releases = Vec::new();
        let mut responses = BTreeMap::new();
        policy_release(
            &mut releases,
            &mut responses,
            REPOSITORY_URL,
            "1.0.0",
            b"qualified root",
            Vec::new(),
        );
        mutate_release_manifest(
            &mut responses,
            REPOSITORY_URL,
            "rules/v1.0.0",
            None,
            |manifest| manifest["qualification"] = qualification,
        );
        let request = default_preferred_request();
        let outcome = prepare_outcome(
            cache.path(),
            &engine_profile("9.9.0"),
            &request,
            false,
            false,
            &FakeTransport::new(responses),
        );
        assert_eq!(
            outcome["failure"]["class"], expected_class,
            "{name}: {}",
            outcome["failure"]["message"]
        );
        assert_eq!(
            outcome["rejections"][0]["reason"],
            match expected_class {
                "pending" => "qualification-pending",
                "integrity" => "qualification-integrity-failed",
                "unqualified" => "qualification-behavior-failed",
                _ => unreachable!(),
            }
        );
        assert_golden(name, outcome, cache.path());
    }

    for (name, qualification, expected_class) in [
        (
            "dependency-pending-qualification",
            json!({
                "integrity": { "status": "verified", "evidence": ["fixture integrity"] },
                "behavior": { "status": "pending", "evidence": [] },
            }),
            "pending",
        ),
        (
            "dependency-integrity-qualification-failed",
            json!({
                "integrity": { "status": "failed", "evidence": ["fixture integrity failed"] },
                "behavior": { "status": "qualified", "evidence": ["fixture behavior"] },
            }),
            "integrity",
        ),
        (
            "dependency-behavior-qualification-failed",
            json!({
                "integrity": { "status": "verified", "evidence": ["fixture integrity"] },
                "behavior": { "status": "failed", "evidence": ["fixture behavior failed"] },
            }),
            "unqualified",
        ),
    ] {
        let cache = tempdir().expect("temporary dependency-qualification cache");
        let mut releases = Vec::new();
        let mut responses = BTreeMap::new();
        native_dependency_release(&mut releases, &mut responses, REPOSITORY_URL, "1.0.0");
        mutate_release_manifest(
            &mut responses,
            REPOSITORY_URL,
            "packs/v1.0.0",
            None,
            |manifest| manifest["qualification"] = qualification,
        );
        policy_release(
            &mut releases,
            &mut responses,
            REPOSITORY_URL,
            "1.0.0",
            b"dependency root",
            dependency_root_manifest("1.0.0", REPOSITORY_URL)
                .as_array()
                .expect("one root dependency")
                .clone(),
        );
        let request = default_preferred_request();
        let outcome = prepare_outcome(
            cache.path(),
            &engine_profile("9.9.0"),
            &request,
            false,
            false,
            &FakeTransport::new(responses),
        );
        assert_eq!(outcome["failure"]["class"], expected_class, "{name}");
        assert_eq!(
            outcome["rejections"][0]["reason"],
            match expected_class {
                "pending" => "qualification-pending",
                "integrity" => "qualification-integrity-failed",
                "unqualified" => "qualification-behavior-failed",
                _ => unreachable!(),
            }
        );
        assert_golden(name, outcome, cache.path());
    }
}

#[test]
fn acquisition_fresh_and_cached_absence_match_golden_outcomes() {
    let cache = tempdir().expect("temporary fresh-empty-inventory cache");
    let request = default_preferred_request();
    let transport = FakeTransport::new(BTreeMap::from([(
        release_listing_url(REPOSITORY_URL),
        b"[]".to_vec(),
    )]));
    let outcome = prepare_outcome(
        cache.path(),
        &engine_profile("9.9.0"),
        &request,
        false,
        false,
        &transport,
    );
    assert_eq!(outcome["failure"]["class"], "no-compatible-release");
    assert_eq!(outcome["inventory"]["fetched_online"], true);
    assert_golden("fresh-inventory-no-candidate", outcome, cache.path());

    let cache = tempdir().expect("temporary cached-empty-inventory cache");
    write_empty_cached_inventory(cache.path(), SystemTime::now());
    let transport = FakeTransport::new(BTreeMap::new());
    let outcome = prepare_outcome(
        cache.path(),
        &engine_profile("9.9.0"),
        &request,
        false,
        false,
        &transport,
    );
    assert_eq!(outcome["failure"]["class"], "unavailable");
    assert_eq!(outcome["failure"]["retryable"], true);
    assert_eq!(transport.call_count(), 0);
    assert_golden(
        "cached-inventory-cannot-prove-absence",
        outcome,
        cache.path(),
    );
}

#[test]
fn acquisition_private_access_and_transport_failures_match_goldens() {
    let mut rate_limit_headers = ureq::http::HeaderMap::new();
    rate_limit_headers.insert(
        "x-ratelimit-remaining",
        ureq::http::HeaderValue::from_static("0"),
    );
    for (name, status, authenticated, headers) in [
        (
            "private-expired-token-401",
            401,
            true,
            ureq::http::HeaderMap::new(),
        ),
        (
            "private-forbidden-403",
            403,
            true,
            ureq::http::HeaderMap::new(),
        ),
        ("private-rate-limited-403", 403, true, rate_limit_headers),
        (
            "private-hidden-listing-404",
            404,
            true,
            ureq::http::HeaderMap::new(),
        ),
    ] {
        let cache = tempdir().expect("temporary private-access cache");
        let request = preferred_request("bifrost.premium", PRIVATE_REPOSITORY);
        let transport = FakeTransport::with_failures(BTreeMap::from([(
            release_listing_url(PRIVATE_REPOSITORY),
            TransportError::http_status(status, authenticated, &headers),
        )]));
        let outcome = prepare_outcome(
            cache.path(),
            &engine_profile("9.9.0"),
            &request,
            false,
            false,
            &transport,
        );
        let expected_class = if name == "private-rate-limited-403" {
            "unavailable"
        } else {
            "access-denied"
        };
        assert_eq!(outcome["failure"]["class"], expected_class, "{name}");
        assert_eq!(outcome["selection"], Value::Null, "{name}");
        assert_eq!(transport.call_count(), 1, "{name}");
        if name == "private-hidden-listing-404" {
            assert_eq!(
                transport.called_urls(),
                vec![release_listing_url(PRIVATE_REPOSITORY)]
            );
            assert!(
                !transport
                    .called_urls()
                    .iter()
                    .any(|url| url.contains("BrokkAi/bifrost-packs"))
            );
        }
        assert_golden(name, outcome, cache.path());
    }

    let cache = tempdir().expect("temporary reachable-private-cache");
    let mut releases = Vec::new();
    let mut responses = BTreeMap::new();
    add_premium_release(&mut releases, &mut responses, PRIVATE_REPOSITORY);
    let request = preferred_request("bifrost.premium", PRIVATE_REPOSITORY);
    let transport = FakeTransport::new(responses);
    let outcome = prepare_outcome(
        cache.path(),
        &premium_engine_profile(),
        &request,
        false,
        false,
        &transport,
    );
    assert_eq!(outcome["status"], "selected");
    assert_golden(
        "private-registry-authorized-response",
        outcome,
        cache.path(),
    );

    for (name, failure) in [
        (
            "registry-timeout",
            TransportError::unavailable("fixture request timed out"),
        ),
        (
            "registry-5xx",
            TransportError::http_status(503, false, &ureq::http::HeaderMap::new()),
        ),
        (
            "registry-429",
            TransportError::http_status(429, false, &ureq::http::HeaderMap::new()),
        ),
    ] {
        let cache = tempdir().expect("temporary transient-failure cache");
        let request = default_preferred_request();
        let transport = FakeTransport::with_failures(BTreeMap::from([(
            release_listing_url(REPOSITORY_URL),
            failure,
        )]));
        let outcome = prepare_outcome(
            cache.path(),
            &engine_profile("9.9.0"),
            &request,
            false,
            false,
            &transport,
        );
        assert_eq!(outcome["failure"]["class"], "unavailable", "{name}");
        assert_eq!(outcome["failure"]["retryable"], true, "{name}");
        assert_golden(name, outcome, cache.path());
    }
}

#[test]
fn acquisition_invalid_inputs_and_sanitized_errors_match_goldens() {
    let profile = engine_profile("9.9.0");
    let cache = tempdir().expect("temporary invalid-request cache");
    let malformed = parse_pack_request(b"{not-json").expect_err("invalid request JSON");
    assert_eq!(malformed.failure_class().name, "invalid-configuration");
    assert_golden(
        "invalid-request-json",
        outcome_for_request_error(&profile, malformed),
        cache.path(),
    );

    let invalid_source_bytes = serde_json::to_vec(&json!({
        "request_schema_version": 1,
        "pack_id": RULES_PACK_ID,
        "repository": "https://github.com/example/private-packs?token=should-not-leak",
        "selection": { "mode": "preferred" },
    }))
    .expect("serialize invalid-source request");
    let invalid_source =
        parse_pack_request(&invalid_source_bytes).expect_err("query string is an invalid source");
    assert_eq!(invalid_source.failure_class().name, "invalid-source");
    assert_golden(
        "invalid-source-url",
        outcome_for_request_error(&profile, invalid_source),
        cache.path(),
    );

    let cache = tempdir().expect("temporary response-sanitization cache");
    let request = default_preferred_request();
    let transport = FakeTransport::new(BTreeMap::from([(
        release_listing_url(REPOSITORY_URL),
        RESPONSE_BODY_MARKER.as_bytes().to_vec(),
    )]));
    let outcome = prepare_outcome(cache.path(), &profile, &request, false, false, &transport);
    let serialized = serde_json::to_vec(&outcome).expect("serialize sanitized outcome");
    assert!(!String::from_utf8_lossy(&serialized).contains(TEST_TOKEN));
    assert!(!String::from_utf8_lossy(&serialized).contains(RESPONSE_BODY_MARKER));
    assert_eq!(outcome["failure"]["class"], "invalid-manifest");
    assert_golden(
        "response-body-and-credential-sanitization",
        outcome,
        cache.path(),
    );
}

#[test]
fn acquisition_corrupt_descriptor_archive_and_extraction_match_goldens() {
    let request = default_preferred_request();
    let profile = engine_profile("9.9.0");

    let cache = tempdir().expect("temporary descriptor-cache");
    let mut releases = Vec::new();
    let mut responses = BTreeMap::new();
    let manifest_digest = policy_release(
        &mut releases,
        &mut responses,
        REPOSITORY_URL,
        "1.0.0",
        b"descriptor",
        Vec::new(),
    );
    let warm_transport = FakeTransport::new(responses);
    prepare_result(
        cache.path(),
        &profile,
        &request,
        false,
        false,
        &warm_transport,
    )
    .expect("initial descriptor acquisition");
    let descriptor_path = cache
        .path()
        .join("manifests")
        .join(format!("{manifest_digest}.json"));
    fs::write(&descriptor_path, b"tampered descriptor bytes")
        .expect("tamper cached descriptor bytes");
    let outcome = prepare_outcome(
        cache.path(),
        &profile,
        &request,
        true,
        false,
        &FakeTransport::new(BTreeMap::new()),
    );
    assert_eq!(outcome["failure"]["class"], "integrity");
    assert_golden("cached-descriptor-digest-mismatch", outcome, cache.path());

    let cache = tempdir().expect("temporary archive-cache");
    let mut releases = Vec::new();
    let mut responses = BTreeMap::new();
    policy_release(
        &mut releases,
        &mut responses,
        REPOSITORY_URL,
        "1.0.0",
        b"archive",
        Vec::new(),
    );
    replace_release_artifact_bytes(
        &mut responses,
        REPOSITORY_URL,
        "rules/v1.0.0",
        "rules.tar.gz",
        b"corrupt archive bytes",
    );
    let outcome = prepare_outcome(
        cache.path(),
        &profile,
        &request,
        false,
        false,
        &FakeTransport::new(responses),
    );
    assert_eq!(outcome["failure"]["class"], "integrity");
    assert_golden("corrupt-archive-bytes", outcome, cache.path());

    let cache = tempdir().expect("temporary extracted-tree cache");
    let mut releases = Vec::new();
    let mut responses = BTreeMap::new();
    policy_release(
        &mut releases,
        &mut responses,
        REPOSITORY_URL,
        "1.0.0",
        b"extract",
        Vec::new(),
    );
    let first = prepare_result(
        cache.path(),
        &profile,
        &request,
        false,
        false,
        &FakeTransport::new(responses),
    )
    .expect("initial extraction acquisition");
    fs::write(
        first.policy_pack_root.join("fixture/policy.rql"),
        b"tampered extracted bytes",
    )
    .expect("tamper cached extracted content");
    let outcome = prepare_outcome(
        cache.path(),
        &profile,
        &request,
        true,
        false,
        &FakeTransport::new(BTreeMap::new()),
    );
    assert_eq!(outcome["failure"]["class"], "integrity");
    assert_golden("tampered-cached-extraction", outcome, cache.path());
}

#[test]
fn acquisition_cache_and_replay_lifecycle_match_goldens() {
    {
        let cache = tempdir().expect("temporary cold-warm-offline cache");
        let mut releases = Vec::new();
        let mut responses = BTreeMap::new();
        policy_release(
            &mut releases,
            &mut responses,
            REPOSITORY_URL,
            "1.0.0",
            b"reused bytes",
            Vec::new(),
        );
        let request = default_preferred_request();
        let profile = engine_profile("9.9.0");
        let cold = prepare_result(
            cache.path(),
            &profile,
            &request,
            false,
            false,
            &FakeTransport::new(responses),
        )
        .expect("cold acquisition");
        let first_id = cold.selection_id.clone();
        let warm = prepare_result(
            cache.path(),
            &profile,
            &request,
            false,
            false,
            &FakeTransport::new(BTreeMap::new()),
        )
        .expect("warm online reuse");
        assert!(warm.cache_reused);
        assert_eq!(warm.selection_id, first_id);
        let offline = prepare_result(
            cache.path(),
            &profile,
            &request,
            true,
            false,
            &FakeTransport::new(BTreeMap::new()),
        )
        .expect("offline warm reuse");
        assert!(offline.cache_reused);
        assert_eq!(offline.selection_id, first_id);
        assert_golden(
            "cold-warm-offline-reuse",
            complete_outcome(&profile, Some(&request), Ok(offline)),
            cache.path(),
        );
    }

    {
        let cache = tempdir().expect("temporary changed-engine-identity cache");
        let mut releases = Vec::new();
        let mut responses = BTreeMap::new();
        policy_release(
            &mut releases,
            &mut responses,
            REPOSITORY_URL,
            "1.0.0",
            b"build-bound bytes",
            Vec::new(),
        );
        let request = default_preferred_request();
        let first_profile = engine_profile("9.9.0");
        let cold = prepare_result(
            cache.path(),
            &first_profile,
            &request,
            false,
            false,
            &FakeTransport::new(responses),
        )
        .expect("first engine identity acquisition");
        let mut changed_profile = first_profile.clone();
        changed_profile.build_identity = "different-fixture-build".to_owned();
        let changed = prepare_result(
            cache.path(),
            &changed_profile,
            &request,
            true,
            false,
            &FakeTransport::new(BTreeMap::new()),
        )
        .expect("changed build identity creates a cold selection from cached inputs");
        assert_ne!(changed.selection_id, cold.selection_id);
        assert!(!changed.cache_reused);
        assert_golden(
            "changed-engine-identity-new-selection",
            complete_outcome(&changed_profile, Some(&request), Ok(changed)),
            cache.path(),
        );
    }

    {
        let cache = tempdir().expect("temporary replay cache");
        let mut releases = Vec::new();
        let mut responses = BTreeMap::new();
        policy_release(
            &mut releases,
            &mut responses,
            REPOSITORY_URL,
            "1.0.0",
            b"receipt replay bytes",
            Vec::new(),
        );
        let request = default_preferred_request();
        let profile = engine_profile("9.9.0");
        let cold = prepare_result(
            cache.path(),
            &profile,
            &request,
            false,
            false,
            &FakeTransport::new(responses),
        )
        .expect("initial replayable selection");
        let receipt = serde_json::from_slice::<Value>(
            &fs::read(&cold.receipt_path).expect("read replayable receipt"),
        )
        .expect("parse replayable receipt");
        let replay = parse_pack_request(
            &serde_json::to_vec(&receipt["replay"]).expect("serialize replay request"),
        )
        .expect("parse receipt replay request");
        let replayed = prepare_result(
            cache.path(),
            &profile,
            &replay,
            true,
            false,
            &FakeTransport::new(BTreeMap::new()),
        )
        .expect("receipt replay selects identical bytes offline");
        assert_eq!(replayed.selection_id, cold.selection_id);
        assert!(replayed.cache_reused);
        assert_eq!(
            fs::read(replayed.policy_pack_root.join("fixture/policy.rql"))
                .expect("read replayed policy bytes"),
            b"receipt replay bytes"
        );
        assert_golden(
            "receipt-replay-identical-bytes-offline",
            complete_outcome(&profile, Some(&replay), Ok(replayed)),
            cache.path(),
        );
    }

    {
        let cache = tempdir().expect("temporary inventory-change replay cache");
        let mut releases = Vec::new();
        let mut responses = BTreeMap::new();
        policy_release(
            &mut releases,
            &mut responses,
            REPOSITORY_URL,
            "1.0.0",
            b"old inventory bytes",
            Vec::new(),
        );
        let request = default_preferred_request();
        let profile = engine_profile("9.9.0");
        let cold = prepare_result(
            cache.path(),
            &profile,
            &request,
            false,
            false,
            &FakeTransport::new(responses.clone()),
        )
        .expect("initial older release selection");
        let old_id = cold.selection_id.clone();
        policy_release(
            &mut releases,
            &mut responses,
            REPOSITORY_URL,
            "1.1.0",
            b"new inventory bytes",
            Vec::new(),
        );
        let newer = prepare_result(
            cache.path(),
            &profile,
            &request,
            false,
            true,
            &FakeTransport::new(responses),
        )
        .expect("refresh discovers and selects newer preferred alternative");
        assert_ne!(newer.selection_id, old_id);
        let newer_version = serde_json::from_slice::<Value>(
            &fs::read(&newer.receipt_path).expect("read newer receipt"),
        )
        .expect("parse newer receipt")["releases"][0]["release_version"]
            .as_str()
            .expect("newer release version")
            .to_owned();
        assert_eq!(newer_version, "1.1.0");
        assert_golden(
            "inventory-change-preferred-selects-newer",
            complete_outcome(&profile, Some(&request), Ok(newer)),
            cache.path(),
        );
    }

    {
        let cache = tempdir().expect("temporary moved-tag replay cache");
        let mut releases = Vec::new();
        let mut responses = BTreeMap::new();
        policy_release(
            &mut releases,
            &mut responses,
            REPOSITORY_URL,
            "1.0.0",
            b"pinned manifest bytes",
            Vec::new(),
        );
        let request = default_preferred_request();
        let profile = engine_profile("9.9.0");
        let cold = prepare_result(
            cache.path(),
            &profile,
            &request,
            false,
            false,
            &FakeTransport::new(responses.clone()),
        )
        .expect("initial moved-tag selection");
        let receipt = serde_json::from_slice::<Value>(
            &fs::read(&cold.receipt_path).expect("read pinned receipt"),
        )
        .expect("parse pinned receipt");
        let replay = parse_pack_request(
            &serde_json::to_vec(&receipt["replay"]).expect("serialize pinned replay"),
        )
        .expect("parse pinned replay");
        mutate_release_manifest(
            &mut responses,
            REPOSITORY_URL,
            "rules/v1.0.0",
            None,
            |manifest| {
                manifest["qualification"]["behavior"]["evidence"] =
                    json!(["manifest bytes changed after selection"]);
            },
        );
        let outcome = complete_outcome(
            &profile,
            Some(&replay),
            prepare_result(
                cache.path(),
                &profile,
                &replay,
                false,
                true,
                &FakeTransport::new(responses),
            ),
        );
        assert_eq!(outcome["failure"]["class"], "integrity");
        assert_golden(
            "replay-fails-after-tag-manifest-moves",
            outcome,
            cache.path(),
        );
    }

    {
        let cache = tempdir().expect("temporary missing-artifact replay cache");
        let mut releases = Vec::new();
        let mut responses = BTreeMap::new();
        policy_release(
            &mut releases,
            &mut responses,
            REPOSITORY_URL,
            "1.0.0",
            b"artifact replay",
            Vec::new(),
        );
        let request = default_preferred_request();
        let profile = engine_profile("9.9.0");
        let cold = prepare_result(
            cache.path(),
            &profile,
            &request,
            false,
            false,
            &FakeTransport::new(responses),
        )
        .expect("initial artifact selection");
        let receipt = serde_json::from_slice::<Value>(
            &fs::read(&cold.receipt_path).expect("read artifact receipt"),
        )
        .expect("parse artifact receipt");
        let replay = parse_pack_request(
            &serde_json::to_vec(&receipt["replay"]).expect("serialize artifact replay"),
        )
        .expect("parse artifact replay");
        let artifact_path = receipt["artifacts"][0]["cache_path"]
            .as_str()
            .expect("artifact cache path");
        fs::remove_file(artifact_path).expect("remove cached artifact for offline replay");
        let outcome = prepare_outcome(
            cache.path(),
            &profile,
            &replay,
            true,
            false,
            &FakeTransport::new(BTreeMap::new()),
        );
        assert_eq!(outcome["failure"]["class"], "offline-cache-miss");
        assert_golden(
            "replay-fails-with-artifact-gone-offline",
            outcome,
            cache.path(),
        );
    }
}

#[test]
fn prerelease_channel_admits_prerelease_with_wildcard_range() {
    let cache = tempdir().expect("temporary wildcard prerelease cache");
    let mut releases = Vec::new();
    let mut responses = BTreeMap::new();
    policy_release(
        &mut releases,
        &mut responses,
        REPOSITORY_URL,
        "1.0.0",
        b"stable policy",
        Vec::new(),
    );
    policy_release(
        &mut releases,
        &mut responses,
        REPOSITORY_URL,
        "1.1.0-rc.1",
        b"prerelease policy",
        Vec::new(),
    );
    mutate_release_manifest(
        &mut responses,
        REPOSITORY_URL,
        "rules/v1.1.0-rc.1",
        Some(true),
        |_| {},
    );
    let request = request_with_selection(
        RULES_PACK_ID,
        REPOSITORY_URL,
        PackSelection::Preferred {
            preferred_version: None,
            allowed_versions: "*".to_owned(),
            channel: PackChannel::Prerelease,
        },
        Vec::new(),
    );
    let outcome = prepare_outcome(
        cache.path(),
        &engine_profile("9.9.0"),
        &request,
        false,
        false,
        &FakeTransport::new(responses),
    );
    assert_golden(
        "prerelease-channel-wildcard-admits-prerelease",
        outcome.clone(),
        cache.path(),
    );
    assert_eq!(
        outcome["selection"]["receipt"]["releases"][0]["release_version"],
        "1.1.0-rc.1"
    );
}

#[test]
fn replay_of_old_selection_survives_inventory_refresh() {
    let cache = tempdir().expect("temporary replay inventory-change cache");
    let mut releases = Vec::new();
    let mut responses = BTreeMap::new();
    policy_release(
        &mut releases,
        &mut responses,
        REPOSITORY_URL,
        "1.0.0",
        b"old inventory bytes",
        Vec::new(),
    );
    let request = default_preferred_request();
    let profile = engine_profile("9.9.0");
    let cold = prepare_result(
        cache.path(),
        &profile,
        &request,
        false,
        false,
        &FakeTransport::new(responses.clone()),
    )
    .expect("initial older release selection");
    let old_id = cold.selection_id.clone();
    let old_receipt =
        serde_json::from_slice::<Value>(&fs::read(&cold.receipt_path).expect("read old receipt"))
            .expect("parse old receipt");
    let replay = parse_pack_request(
        &serde_json::to_vec(&old_receipt["replay"]).expect("serialize old replay"),
    )
    .expect("parse old receipt replay");
    policy_release(
        &mut releases,
        &mut responses,
        REPOSITORY_URL,
        "1.1.0",
        b"new inventory bytes",
        Vec::new(),
    );
    let newer = prepare_result(
        cache.path(),
        &profile,
        &request,
        false,
        true,
        &FakeTransport::new(responses),
    )
    .expect("refresh discovers newer preferred release");
    assert_ne!(newer.selection_id, old_id);
    let result = prepare_result(
        cache.path(),
        &profile,
        &replay,
        true,
        false,
        &FakeTransport::new(BTreeMap::new()),
    );
    let outcome = complete_outcome(&profile, Some(&replay), result);
    assert_golden(
        "inventory-change-replay-keeps-old-bytes",
        outcome.clone(),
        cache.path(),
    );
    assert_eq!(outcome["status"], "selected");
    assert_eq!(outcome["selection"]["selection_id"], old_id);
}

#[test]
fn acquisition_release_enumeration_order_is_golden_and_independent() {
    let first_cache = tempdir().expect("temporary forward-order cache");
    let mut releases = Vec::new();
    let mut forward = BTreeMap::new();
    policy_release(
        &mut releases,
        &mut forward,
        REPOSITORY_URL,
        "1.0.0",
        b"one",
        Vec::new(),
    );
    policy_release(
        &mut releases,
        &mut forward,
        REPOSITORY_URL,
        "2.0.0",
        b"two",
        Vec::new(),
    );
    let request = default_preferred_request();
    let profile = engine_profile("9.9.0");
    let first = prepare_outcome(
        first_cache.path(),
        &profile,
        &request,
        false,
        false,
        &FakeTransport::new(forward.clone()),
    );
    assert_eq!(
        first["selection"]["receipt"]["releases"][0]["release_version"],
        "2.0.0"
    );
    assert_golden(
        "release-enumeration-order-independence",
        first.clone(),
        first_cache.path(),
    );

    let reverse_cache = tempdir().expect("temporary reverse-order cache");
    reverse_release_listing(&mut forward, REPOSITORY_URL);
    let second = prepare_outcome(
        reverse_cache.path(),
        &profile,
        &request,
        false,
        false,
        &FakeTransport::new(forward),
    );
    assert_eq!(
        normalize_outcome(first, first_cache.path()),
        normalize_outcome(second, reverse_cache.path()),
        "normalized outcome must be byte-identical for reversed registry enumeration"
    );
}

#[test]
fn acquisition_same_version_rerelease_is_a_golden_invalid_manifest() {
    let cache = tempdir().expect("temporary same-version re-release cache");
    let mut releases = Vec::new();
    let mut responses = BTreeMap::new();
    policy_release_with_tag_override(
        &mut releases,
        &mut responses,
        REPOSITORY_URL,
        "1.0.0+rerel.1",
        b"first release bytes",
        Vec::new(),
        Some("rules/v1.0.0+rerel.1"),
    );
    policy_release_with_tag_override(
        &mut releases,
        &mut responses,
        REPOSITORY_URL,
        "1.0.0+rerel.2",
        b"re-released bytes",
        Vec::new(),
        Some("rules/v1.0.0+rerel.2"),
    );
    let request = default_preferred_request();
    let outcome = prepare_outcome(
        cache.path(),
        &engine_profile("9.9.0"),
        &request,
        false,
        false,
        &FakeTransport::new(responses),
    );
    assert_golden(
        "same-version-rerelease-invalid-manifest",
        outcome.clone(),
        cache.path(),
    );
    assert_eq!(outcome["failure"]["class"], "invalid-manifest");
}

#[test]
fn repeated_release_tag_is_a_golden_integrity_failure() {
    let cache = tempdir().expect("temporary repeated-tag cache");
    let mut releases = Vec::new();
    let mut responses = BTreeMap::new();
    policy_release(
        &mut releases,
        &mut responses,
        REPOSITORY_URL,
        "1.0.0",
        b"first release bytes",
        Vec::new(),
    );
    policy_release_with_tag_override(
        &mut releases,
        &mut responses,
        REPOSITORY_URL,
        "2.0.0",
        b"duplicate tag bytes",
        Vec::new(),
        Some("rules/v1.0.0"),
    );
    let request = default_preferred_request();
    let outcome = prepare_outcome(
        cache.path(),
        &engine_profile("9.9.0"),
        &request,
        false,
        false,
        &FakeTransport::new(responses),
    );
    assert_golden(
        "repeated-release-tag-integrity",
        outcome.clone(),
        cache.path(),
    );
    assert_eq!(outcome["failure"]["class"], "integrity");
}

#[test]
fn every_acquisition_golden_and_embedded_contract_object_matches_its_schema() {
    if std::env::var("BIFROST_BLESS").as_deref() == Ok("1") {
        return;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/acquisition");
    let (request_validator, receipt_validator, outcome_validator) = request_schema_validators();
    let mut files = Vec::new();
    let mut pending = vec![root.clone()];
    while let Some(directory) = pending.pop() {
        for item in fs::read_dir(&directory).expect("read acquisition fixture directory") {
            let item = item.expect("read acquisition fixture entry");
            let path = item.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.file_name().is_some_and(|name| name == "expected.json") {
                files.push(path);
            }
        }
    }
    files.sort();
    assert!(!files.is_empty(), "acquisition golden fixtures are present");
    for path in files {
        let outcome = serde_json::from_slice::<Value>(
            &fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
        )
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
        let outcome_errors = outcome_validator.iter_errors(&outcome).collect::<Vec<_>>();
        assert!(
            outcome_errors.is_empty(),
            "outcome schema rejected {}: {outcome_errors:#?}",
            path.display()
        );
        if outcome["request"].is_object() {
            let errors = request_validator
                .iter_errors(&outcome["request"])
                .collect::<Vec<_>>();
            assert!(
                errors.is_empty(),
                "request schema rejected {}: {errors:#?}",
                path.display()
            );
        }
        if let Some(receipt) = outcome["selection"]["receipt"].as_object() {
            let receipt = Value::Object(receipt.clone());
            let errors = receipt_validator.iter_errors(&receipt).collect::<Vec<_>>();
            assert!(
                errors.is_empty(),
                "receipt schema rejected {}: {errors:#?}",
                path.display()
            );
            let errors = request_validator
                .iter_errors(&receipt["replay"])
                .collect::<Vec<_>>();
            assert!(
                errors.is_empty(),
                "replay request schema rejected {}: {errors:#?}",
                path.display()
            );
        }
    }
}

#[path = "conformance_tests.rs"]
mod release_conformance;
