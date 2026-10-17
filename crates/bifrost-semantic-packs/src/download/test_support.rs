use super::*;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::{Cursor, Write};
use std::sync::Mutex;
use tar::Builder;
use zip::System;
use zip::write::{SimpleFileOptions, ZipWriter};

pub(super) const TEST_COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

pub(super) struct FakeTransport {
    responses: BTreeMap<String, Vec<u8>>,
    failures: BTreeMap<String, TransportError>,
    pub(super) calls: Mutex<Vec<String>>,
}

impl FakeTransport {
    pub(super) fn new(responses: BTreeMap<String, Vec<u8>>) -> Self {
        Self {
            responses,
            failures: BTreeMap::new(),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn with_failures(failures: BTreeMap<String, TransportError>) -> Self {
        Self {
            responses: BTreeMap::new(),
            failures,
            calls: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn call_count(&self) -> usize {
        self.calls.lock().expect("fake call lock").len()
    }

    pub(super) fn called_urls(&self) -> Vec<String> {
        self.calls.lock().expect("fake call lock").clone()
    }
}

impl HttpTransport for FakeTransport {
    fn fetch(&self, url: &str, _max_bytes: u64) -> Result<Vec<u8>, TransportError> {
        self.calls
            .lock()
            .expect("fake call lock")
            .push(url.to_owned());
        if let Some(error) = self.failures.get(url) {
            return Err(error.clone());
        }
        self.responses.get(url).cloned().ok_or_else(|| {
            TransportError::unavailable(format!("fixture has no response for {url}"))
        })
    }
}

pub(super) fn write_empty_cached_inventory(root: &Path, fetched_at: SystemTime) {
    fs::create_dir_all(root).expect("create cached inventory root");
    let index = ManifestIndex {
        schema_version: INVENTORY_SCHEMA_VERSION,
        fetched_at: format_iso_utc(fetched_at).expect("format cached inventory timestamp"),
        source: Some(PackSource {
            repository: REPOSITORY_URL.to_owned(),
            inventory_url: None,
            inventory_sha256: None,
        }),
        releases: Vec::new(),
    };
    fs::write(
        root.join("manifest-index.json"),
        serde_json::to_vec(&index).expect("encode cached inventory"),
    )
    .expect("write cached inventory");
}

pub(super) fn schema_json() -> Value {
    json!({
        "policy_document": [1],
        "rql": [1],
        "builtin_catalog": [1],
        "policy_bundle": [],
        "semantic_model_read": [1],
        "semantic_model_write": [1],
        "semantic_spec": [1],
        "release_index": [1],
        "runtime": [1],
    })
}

pub(super) fn engine_profile(engine_version: &str) -> EngineProfile {
    serde_json::from_value(json!({
        "build_identity": "fixture-build",
        "capabilities": [],
        "capability_contract_version": 1,
        "engine_version": engine_version,
        "model_set_sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "schemas": schema_json(),
    }))
    .expect("valid test engine profile")
}

pub(super) fn premium_engine_profile() -> EngineProfile {
    let mut profile = engine_profile("9.9.0");
    profile.schemas.policy_bundle = vec![1];
    profile.capabilities = vec![
        "actual-to-formal-binding".to_owned(),
        "exact-call-target".to_owned(),
        "flow".to_owned(),
        "taint".to_owned(),
    ];
    profile
}

pub(super) fn release_listing_url(repository: &str) -> String {
    let repository_path = repository
        .strip_prefix("https://github.com")
        .expect("fixture repository is on GitHub");
    format!("https://api.github.com/repos{repository_path}/releases?per_page=100&page=1")
}

pub(super) fn set_release_listing(
    responses: &mut BTreeMap<String, Vec<u8>>,
    repository: &str,
    releases: &[Value],
) {
    responses.insert(
        release_listing_url(repository),
        serde_json::to_vec(releases).expect("serialize fixture release listing"),
    );
}

pub(super) fn reverse_release_listing(responses: &mut BTreeMap<String, Vec<u8>>, repository: &str) {
    let url = release_listing_url(repository);
    let mut releases = serde_json::from_slice::<Vec<Value>>(
        responses
            .get(&url)
            .expect("fixture release listing response"),
    )
    .expect("parse fixture release listing");
    releases.reverse();
    set_release_listing(responses, repository, &releases);
}

pub(super) fn mutate_release_manifest(
    responses: &mut BTreeMap<String, Vec<u8>>,
    repository: &str,
    tag: &str,
    github_prerelease: Option<bool>,
    mutate: impl FnOnce(&mut Value),
) -> String {
    let listing_url = release_listing_url(repository);
    let mut releases = serde_json::from_slice::<Vec<Value>>(
        responses
            .get(&listing_url)
            .expect("fixture release listing response"),
    )
    .expect("parse fixture release listing");
    let release = releases
        .iter_mut()
        .find(|release| release["tag_name"] == tag)
        .expect("fixture release tag");
    if let Some(prerelease) = github_prerelease {
        release["prerelease"] = json!(prerelease);
    }
    let descriptor_asset = release["assets"]
        .as_array()
        .expect("fixture release assets")
        .iter()
        .find(|asset| asset["name"] == "pack-release.json")
        .expect("fixture release descriptor asset");
    let asset_id = descriptor_asset["id"]
        .as_u64()
        .expect("descriptor asset ID");
    let browser_url = descriptor_asset["browser_download_url"]
        .as_str()
        .expect("descriptor browser URL")
        .to_owned();
    let mut manifest = serde_json::from_slice::<Value>(
        responses
            .get(&browser_url)
            .expect("fixture descriptor response"),
    )
    .expect("parse fixture descriptor");
    mutate(&mut manifest);
    let bytes = canonical_json_bytes(&manifest).expect("serialize mutated descriptor");
    let repository_path = repository
        .strip_prefix("https://github.com")
        .expect("fixture repository is on GitHub");
    responses.insert(browser_url, bytes.clone());
    responses.insert(
        format!("https://api.github.com/repos{repository_path}/releases/assets/{asset_id}"),
        bytes.clone(),
    );
    set_release_listing(responses, repository, &releases);
    sha256(&bytes)
}

pub(super) fn replace_release_artifact_bytes(
    responses: &mut BTreeMap<String, Vec<u8>>,
    repository: &str,
    tag: &str,
    artifact_name: &str,
    bytes: &[u8],
) {
    let listing_url = release_listing_url(repository);
    let releases = serde_json::from_slice::<Vec<Value>>(
        responses
            .get(&listing_url)
            .expect("fixture release listing response"),
    )
    .expect("parse fixture release listing");
    let release = releases
        .iter()
        .find(|release| release["tag_name"] == tag)
        .expect("fixture release tag");
    let asset = release["assets"]
        .as_array()
        .expect("fixture release assets")
        .iter()
        .find(|asset| asset["name"] == artifact_name)
        .expect("fixture artifact asset");
    let asset_id = asset["id"].as_u64().expect("artifact asset ID");
    let browser_url = asset["browser_download_url"]
        .as_str()
        .expect("artifact browser URL")
        .to_owned();
    let repository_path = repository
        .strip_prefix("https://github.com")
        .expect("fixture repository is on GitHub");
    responses.insert(browser_url, bytes.to_vec());
    responses.insert(
        format!("https://api.github.com/repos{repository_path}/releases/assets/{asset_id}"),
        bytes.to_vec(),
    );
}

pub(super) fn test_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = Builder::new(encoder);
    for (path, bytes) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(EntryType::Regular);
        header.set_mode(0o644);
        header.set_size(bytes.len() as u64);
        header.set_path(path).expect("set fixture archive path");
        header.set_cksum();
        archive
            .append(&header, Cursor::new(*bytes))
            .expect("append fixture archive file");
    }
    archive
        .into_inner()
        .expect("finish tar archive")
        .finish()
        .expect("finish gzip archive")
}

pub(super) fn test_zip_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let cursor = Cursor::new(Vec::new());
    let mut archive = ZipWriter::new(cursor);
    for (path, bytes) in entries {
        archive
            .start_file(*path, SimpleFileOptions::default().system(System::Unix))
            .expect("start fixture ZIP entry");
        archive.write_all(bytes).expect("write fixture ZIP entry");
    }
    archive
        .finish()
        .expect("finish fixture ZIP archive")
        .into_inner()
}

pub(super) fn test_zip_symlink_archive(path: &str, target: &[u8]) -> Vec<u8> {
    let mut bytes = test_zip_archive(&[(path, target)]);
    let central_directory = bytes
        .windows(4)
        .rposition(|window| window == [b'P', b'K', 1, 2])
        .expect("fixture ZIP central directory");
    bytes[central_directory + 5] = 3;
    bytes[central_directory + 38..central_directory + 42]
        .copy_from_slice(&(0o120777_u32 << 16).to_le_bytes());
    bytes
}

pub(super) fn content_entry(kind: &str, identity: &str, path: &str, bytes: &[u8]) -> Value {
    json!({
        "kind": kind,
        "identity": identity,
        "path": path,
        "sha256": sha256(bytes),
        "languages": [],
        "dependencies": [],
        "schemas": schema_json(),
        "required_capabilities": [],
    })
}

pub(super) struct ReleaseFixture<'a> {
    pub(super) pack_id: &'a str,
    pub(super) version: &'a str,
    pub(super) schema_version: u8,
    pub(super) artifact_role: &'a str,
    pub(super) archive: &'a [u8],
    pub(super) contents: Vec<Value>,
    pub(super) dependencies: Vec<Value>,
}

pub(super) fn artifact_name_for(pack_id: &str) -> &'static str {
    if pack_id == RULES_PACK_ID {
        "rules.tar.gz"
    } else {
        "semantic.tar.gz"
    }
}

pub(super) fn manifest_bytes(fixture: ReleaseFixture<'_>) -> Vec<u8> {
    manifest_bytes_for(fixture, REPOSITORY_URL)
}

pub(super) fn manifest_bytes_for(fixture: ReleaseFixture<'_>, repository: &str) -> Vec<u8> {
    let ReleaseFixture {
        pack_id,
        version,
        schema_version,
        artifact_role,
        archive,
        contents,
        dependencies,
    } = fixture;
    let mut compatibility = json!({
        "schemas": schema_json(),
        "capabilities": { "contract_version": 1, "required": [], "provided": [] },
    });
    if schema_version == 1 {
        compatibility["engine"] = json!({
            "min_inclusive": "1.0.0",
            "max_exclusive": "1000.0.0",
        });
    }
    let qualification = if schema_version == 1 {
        json!({ "status": "qualified", "evidence": ["fixture qualification"] })
    } else {
        json!({
            "integrity": { "status": "verified", "evidence": ["fixture integrity"] },
            "behavior": { "status": "qualified", "evidence": ["fixture behavior"] },
        })
    };
    let mut manifest = json!({
        "manifest_schema_version": schema_version,
        "pack": {
            "id": pack_id,
            "repository": repository,
            "visibility": "public",
        },
        "release_version": version,
        "source": {
            "repository": repository,
            "commit": TEST_COMMIT,
            "dirty": false,
        },
        "compatibility": compatibility,
        "contents": contents,
        "artifacts": [{
            "name": artifact_name_for(pack_id),
            "sha256": sha256(archive),
            "size_bytes": archive.len(),
            "format": "tar.gz",
            "role": artifact_role,
        }],
        "qualification": qualification,
        "release_dependencies": dependencies,
    });
    if schema_version == 2 {
        manifest["provenance"] = json!({
            "engine_version": "0.0.1",
            "build_identity": "older-engine-build",
            "source_commit": TEST_COMMIT,
        });
    }
    canonical_json_bytes(&manifest).expect("serialize test manifest")
}

pub(super) fn add_release(
    releases: &mut Vec<Value>,
    responses: &mut BTreeMap<String, Vec<u8>>,
    fixture: ReleaseFixture<'_>,
) {
    let _ = add_release_for(releases, responses, fixture, REPOSITORY_URL);
}

pub(super) fn add_release_for(
    releases: &mut Vec<Value>,
    responses: &mut BTreeMap<String, Vec<u8>>,
    fixture: ReleaseFixture<'_>,
    repository: &str,
) -> String {
    add_release_for_with_tag_override(releases, responses, fixture, repository, None)
}

pub(super) fn add_release_for_with_tag_override(
    releases: &mut Vec<Value>,
    responses: &mut BTreeMap<String, Vec<u8>>,
    fixture: ReleaseFixture<'_>,
    repository: &str,
    tag_override: Option<&str>,
) -> String {
    let role_name = if fixture.pack_id == RULES_PACK_ID {
        "rules"
    } else {
        "semantic"
    };
    let tag = tag_override
        .map(str::to_owned)
        .unwrap_or_else(|| release_tag(fixture.pack_id, fixture.version));
    let artifact_name = format!("{role_name}.tar.gz");
    let archive = fixture.archive.to_vec();
    let manifest = manifest_bytes_for(fixture, repository);
    let repository_path = repository.strip_prefix("https://github.com").unwrap();
    let manifest_url = format!("{repository}/releases/download/{tag}/pack-release.json");
    let artifact_url = format!("{repository}/releases/download/{tag}/{artifact_name}");
    let api = format!("https://api.github.com/repos{repository_path}");
    let asset_base = 100 + u64::try_from(releases.len()).expect("fixture release count") * 2;
    let (manifest_asset_id, artifact_asset_id) = (asset_base, asset_base + 1);
    let manifest_asset_url = format!("{api}/releases/assets/{manifest_asset_id}");
    let artifact_asset_url = format!("{api}/releases/assets/{artifact_asset_id}");
    let manifest_sha = sha256(&manifest);
    responses.insert(manifest_url.clone(), manifest.clone());
    responses.insert(artifact_url.clone(), archive.clone());
    responses.insert(manifest_asset_url, manifest);
    responses.insert(artifact_asset_url, archive);
    let escaped_tag = tag
        .split('/')
        .map(percent_encode_path_segment)
        .collect::<Vec<_>>()
        .join("/");
    let tag_url = format!("{api}/git/ref/tags/{escaped_tag}");
    responses.insert(
        tag_url,
        serde_json::to_vec(&json!({
            "object": { "sha": TEST_COMMIT, "type": "commit" },
        }))
        .expect("serialize fixture tag"),
    );
    releases.push(json!({
        "tag_name": tag,
        "draft": false,
        "prerelease": false,
        "assets": [
            { "id": manifest_asset_id, "name": "pack-release.json", "browser_download_url": manifest_url },
            { "id": artifact_asset_id, "name": artifact_name, "browser_download_url": artifact_url },
        ],
    }));
    let listing_url = format!("{api}/releases?per_page=100&page=1");
    responses.insert(
        listing_url,
        serde_json::to_vec(releases).expect("serialize fixture release listing"),
    );
    let tag_release_url = format!("{api}/releases/tags/{}", percent_encode_path_segment(&tag));
    responses.insert(
        tag_release_url,
        serde_json::to_vec(&json!({
            "tag_name": tag,
            "draft": false,
            "prerelease": false,
            "assets": [
                { "id": manifest_asset_id, "name": "pack-release.json", "browser_download_url": manifest_url },
                { "id": artifact_asset_id, "name": artifact_name, "browser_download_url": artifact_url },
            ],
        }))
        .expect("serialize explicit source release"),
    );
    manifest_sha
}

pub(super) fn add_premium_release(
    releases: &mut Vec<Value>,
    responses: &mut BTreeMap<String, Vec<u8>>,
    repository: &str,
) -> String {
    let required_capabilities = [
        "actual-to-formal-binding",
        "exact-call-target",
        "flow",
        "taint",
    ];
    let languages = [
        "csharp",
        "cpp",
        "go",
        "java",
        "javascript",
        "kotlin",
        "php",
        "python",
        "ruby",
        "rust",
        "scala",
        "swift",
        "typescript",
        "tsx",
    ];
    let policy_bytes = b"fixture compiled policy";
    let evidence_bytes = b"fixture behavior evidence";
    let policy_entries = languages
        .iter()
        .map(|language| {
            (
                format!("rules/compiled/{language}/premium.rqlp"),
                policy_bytes.as_slice(),
            )
        })
        .collect::<Vec<_>>();
    let borrowed_policy_entries = policy_entries
        .iter()
        .map(|(path, bytes)| (path.as_str(), *bytes))
        .collect::<Vec<_>>();
    let policy_archive = test_zip_archive(&borrowed_policy_entries);
    let evidence_archive = test_zip_archive(&[("evidence/behavior.json", evidence_bytes)]);
    let mut schemas = schema_json();
    schemas["policy_bundle"] = json!([1]);
    let contents = languages
        .iter()
        .map(|language| {
            json!({
                "kind": "policy",
                "identity": format!("bifrost.premium.{language}"),
                "path": format!("rules/compiled/{language}/premium.rqlp"),
                "sha256": sha256(policy_bytes),
                "languages": [language],
                "dependencies": [],
                "schemas": schemas,
                "required_capabilities": required_capabilities,
            })
        })
        .collect::<Vec<_>>();
    let tag = "v0.3.0";
    let manifest = json!({
        "manifest_schema_version": 2,
        "pack": {
            "id": "bifrost.premium",
            "repository": repository,
            "visibility": "private",
        },
        "release_version": "0.3.0",
        "source": {
            "repository": repository,
            "commit": TEST_COMMIT,
            "dirty": false,
        },
        "compatibility": {
            "schemas": schemas,
            "capabilities": {
                "contract_version": 1,
                "required": required_capabilities,
                "provided": [],
            },
        },
        "contents": contents,
        "artifacts": [
            {
                "name": "policy.zip",
                "sha256": sha256(&policy_archive),
                "size_bytes": policy_archive.len(),
                "format": "zip",
                "role": "policy",
            },
            {
                "name": "source.zip",
                "sha256": sha256(&evidence_archive),
                "size_bytes": evidence_archive.len(),
                "format": "zip",
                "role": "source",
            },
        ],
        "qualification": {
            "integrity": { "status": "verified", "evidence": ["fixture integrity"] },
            "behavior": { "status": "limited", "evidence": ["fixture behavior"] },
        },
        "release_dependencies": [],
        "provenance": {
            "engine_version": "0.0.1",
            "build_identity": "fixture-engine",
            "source_commit": TEST_COMMIT,
        },
    });
    let manifest_bytes = canonical_json_bytes(&manifest).expect("serialize premium manifest");
    let manifest_sha = sha256(&manifest_bytes);
    let repository_path = repository
        .strip_prefix("https://github.com")
        .expect("GitHub repository URL");
    let api = format!("https://api.github.com/repos{repository_path}");
    let manifest_asset_id = 900;
    let policy_asset_id = 901;
    let source_asset_id = 902;
    let manifest_url = format!("{repository}/releases/download/{tag}/pack-release.json");
    let policy_url = format!("{repository}/releases/download/{tag}/policy.zip");
    let source_url = format!("{repository}/releases/download/{tag}/source.zip");
    for (url, bytes) in [
        (manifest_url.clone(), manifest_bytes.clone()),
        (policy_url.clone(), policy_archive.clone()),
        (source_url.clone(), evidence_archive.clone()),
        (
            format!("{api}/releases/assets/{manifest_asset_id}"),
            manifest_bytes,
        ),
        (
            format!("{api}/releases/assets/{policy_asset_id}"),
            policy_archive.clone(),
        ),
        (
            format!("{api}/releases/assets/{source_asset_id}"),
            evidence_archive.clone(),
        ),
    ] {
        responses.insert(url, bytes);
    }
    let tag_url = format!("{api}/git/ref/tags/{tag}");
    responses.insert(
        tag_url,
        serde_json::to_vec(&json!({
            "object": { "sha": TEST_COMMIT, "type": "commit" },
        }))
        .expect("serialize premium tag"),
    );
    releases.push(json!({
        "tag_name": tag,
        "draft": false,
        "prerelease": false,
        "assets": [
            { "id": manifest_asset_id, "name": "pack-release.json", "browser_download_url": manifest_url },
            { "id": policy_asset_id, "name": "policy.zip", "browser_download_url": policy_url },
            { "id": source_asset_id, "name": "source.zip", "browser_download_url": source_url },
        ],
    }));
    responses.insert(
        format!("{api}/releases?per_page=100&page=1"),
        serde_json::to_vec(releases).expect("serialize premium listing"),
    );
    manifest_sha
}

pub(super) fn v1_manifest(engine_min: &str, engine_max: &str) -> PackRelease {
    let bytes = manifest_bytes(ReleaseFixture {
        pack_id: SEMANTIC_PACK_ID,
        version: "1.0.0",
        schema_version: 1,
        artifact_role: "native",
        archive: b"x",
        contents: Vec::new(),
        dependencies: Vec::new(),
    });
    let mut value: Value = serde_json::from_slice(&bytes).expect("parse fixture manifest");
    value["compatibility"]["engine"]["min_inclusive"] = json!(engine_min);
    value["compatibility"]["engine"]["max_exclusive"] = json!(engine_max);
    parse_release_manifest(&serde_json::to_vec(&value).unwrap())
        .expect("valid schema 1 manifest")
        .0
}
