use super::super::test_support::FakeTransport;
use super::super::{EngineProfile, PackRequest, acquisition_outcome};
use super::prepare_result;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use tempfile::tempdir;

const CONFORMANCE_SCHEMA_VERSION: u32 = 1;
const PROFILE_ORIGIN: &str = "fixture";
const TRANSPORT: &str = "fake-transport";
const MARKER: &str = "BIFROST_LOADER_CONFORMANCE_V1=";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    fixture_schema_version: u32,
    case_id: String,
    profile_origin: String,
    transport: String,
    control: Scenario,
    case: Scenario,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    profile: Value,
    request: Value,
    response_map: BTreeMap<String, String>,
}

fn run_fixture(
    expected_case_id: &str,
    test_name: &str,
    fixture_bytes: &str,
    required_diagnostic: &str,
    expected_failure_class: &str,
) {
    let fixture = serde_json::from_str::<Fixture>(fixture_bytes).expect("parse frozen fixture");
    assert_eq!(fixture.fixture_schema_version, CONFORMANCE_SCHEMA_VERSION);
    assert_eq!(fixture.case_id, expected_case_id);
    assert_eq!(fixture.profile_origin, PROFILE_ORIGIN);
    assert_eq!(fixture.transport, TRANSPORT);
    let control_profile = parse_profile(&fixture.control);
    let control_request = parse_request(&fixture.control);
    let case_profile = parse_profile(&fixture.case);
    let case_request = parse_request(&fixture.case);
    assert_eq!(fixture.control.profile["build_identity"], "fixture-build");
    assert_eq!(fixture.case.profile["build_identity"], "fixture-build");

    let control_cache = tempdir().expect("create control cache");
    let control_transport = FakeTransport::new(decode_response_map(&fixture.control));
    let control_result = prepare_result(
        control_cache.path(),
        &control_profile,
        &control_request,
        false,
        false,
        &control_transport,
    )
    .expect("coherent fixture control selects");
    let control_outcome = acquisition_outcome(
        &fixture.control.profile,
        Some(&control_request),
        Ok(control_result),
    );
    assert_eq!(control_outcome["status"], "selected");
    assert!(control_outcome["failure"].is_null());
    assert!(control_outcome["selection"].is_object());
    assert_eq!(
        control_outcome["selection"]["receipt"]["request"],
        control_outcome["request"]
    );
    assert_eq!(control_outcome["request"], fixture.control.request);

    let case_cache = tempdir().expect("create defect cache");
    let case_transport = FakeTransport::new(decode_response_map(&fixture.case));
    let case_result = prepare_result(
        case_cache.path(),
        &case_profile,
        &case_request,
        false,
        false,
        &case_transport,
    );
    let case_outcome = acquisition_outcome(&fixture.case.profile, Some(&case_request), case_result);
    assert_eq!(case_outcome["status"], "failed");
    assert_eq!(case_outcome["failure"]["class"], expected_failure_class);
    assert!(case_outcome["selection"].is_null());
    assert!(case_outcome.get("fallback").is_none());
    assert_eq!(case_outcome["request"], fixture.case.request);
    assert_diagnostic(&case_outcome, required_diagnostic);

    let binary = std::env::current_exe().expect("locate current test binary");
    let report = serde_json::json!({
        "conformance_schema_version": CONFORMANCE_SCHEMA_VERSION,
        "case_id": fixture.case_id,
        "test_name": test_name,
        "profile_origin": PROFILE_ORIGIN,
        "transport": TRANSPORT,
        "test_binary_sha256": hash_file(binary),
        "control": {
            "profile": fixture.control.profile,
            "request": fixture.control.request,
            "response_map": fixture.control.response_map,
            "result": control_outcome,
            "calls": control_transport.called_urls(),
        },
        "case": {
            "profile": fixture.case.profile,
            "request": fixture.case.request,
            "response_map": fixture.case.response_map,
            "result": case_outcome,
            "calls": case_transport.called_urls(),
        },
    });
    println!(
        "{MARKER}{}",
        serde_json::to_string(&report).expect("serialize conformance report")
    );
}

fn parse_profile(scenario: &Scenario) -> EngineProfile {
    serde_json::from_value(scenario.profile.clone()).expect("decode fixture engine profile")
}

fn parse_request(scenario: &Scenario) -> PackRequest {
    serde_json::from_value(scenario.request.clone()).expect("decode fixture pack request")
}

fn decode_response_map(scenario: &Scenario) -> BTreeMap<String, Vec<u8>> {
    scenario
        .response_map
        .iter()
        .map(|(url, body)| (url.clone(), decode_hex(body)))
        .collect()
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(
        value.len().is_multiple_of(2),
        "fixture response hex has odd length"
    );
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0]);
            let low = hex_digit(pair[1]);
            high * 16 + low
        })
        .collect()
}

fn hex_digit(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("fixture response map is not lowercase hexadecimal"),
    }
}

fn hash_file(path: impl AsRef<Path>) -> String {
    super::super::hash_file(path.as_ref()).expect("hash current test binary")
}

fn assert_diagnostic(outcome: &Value, required: &str) {
    if outcome["failure"]["class"] == "integrity" {
        assert!(
            outcome["failure"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("SHA-256")),
            "corrupt artifact did not reach the artifact SHA-256 diagnostic: {outcome:#?}"
        );
        return;
    }
    let detail = outcome["rejections"][0]["detail"]
        .as_str()
        .expect("selection rejection has diagnostic detail");
    assert!(
        detail.contains(required),
        "selection rejection does not name {required:?}: {outcome:#?}"
    );
}

#[test]
fn unknown_capability() {
    run_fixture(
        "public-conformance-unknown-capability",
        "download::request_tests::release_conformance::unknown_capability",
        include_str!("conformance-fixtures/unknown-capability.json"),
        "fixture-unknown-capability",
        "incompatible-strict-selection",
    );
}

#[test]
fn missing_capability() {
    run_fixture(
        "public-conformance-missing-capability",
        "download::request_tests::release_conformance::missing_capability",
        include_str!("conformance-fixtures/missing-capability.json"),
        "structural-match",
        "incompatible-strict-selection",
    );
}

#[test]
fn incompatible_schema() {
    run_fixture(
        "public-conformance-incompatible-schema",
        "download::request_tests::release_conformance::incompatible_schema",
        include_str!("conformance-fixtures/incompatible-schema.json"),
        "policy_bundle",
        "incompatible-strict-selection",
    );
}

#[test]
fn corrupt_artifact() {
    run_fixture(
        "public-conformance-corrupt-artifact",
        "download::request_tests::release_conformance::corrupt_artifact",
        include_str!("conformance-fixtures/corrupt-artifact.json"),
        "SHA-256",
        "integrity",
    );
}
