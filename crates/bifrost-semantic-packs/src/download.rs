//! Opt-in acquisition of exact generated semantic-pack productions.
//!
//! The downloader is deliberately downstream of analysis. Analysis supplies
//! the catalog and exact generated-production key; this module only downloads,
//! verifies, and installs a release bundle. Analysis re-reads the generated
//! production after the hook returns, so a downloaded bundle cannot bypass
//! catalog validation.

use std::collections::HashSet;
use std::error::Error;
use std::ffi::OsStr;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use brokk_bifrost_analysis::analyzer::semantic_model::{
    GeneratedProductionKey, SemanticPackCatalog,
};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use tar::Archive;
use tempfile::Builder as TempDirBuilder;

const RELEASE_REPOSITORY: &str = "BrokkAi/bifrost";
const RELEASE_VERSION: &str = env!("CARGO_PKG_VERSION");
const RELEASE_TAG: &str = concat!("v", env!("CARGO_PKG_VERSION"));
const ARCHIVE_NAME: &str = concat!(
    "bifrost-semantic-packs-v",
    env!("CARGO_PKG_VERSION"),
    ".tar.gz"
);
const CHECKSUM_NAME: &str = concat!(
    "bifrost-semantic-packs-v",
    env!("CARGO_PKG_VERSION"),
    ".tar.gz.sha256"
);
const EXPECTED_TOP_LEVEL: &str = "bifrost-semantic-packs";
const DOWNLOAD_MODE_ENV: &str = "BIFROST_SEMANTIC_PACK_DOWNLOAD";
const DOWNLOAD_CACHE_DIR: &str = "semantic-pack-downloads";
const USER_AGENT_PREFIX: &str = "brokk-bifrost-semantic-packs";
const MAX_REDIRECTS: u32 = 3;
const GLOBAL_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CHECKSUM_BYTES: u64 = 4 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_EXTRACTED_BYTES: u64 = 512 * 1024 * 1024;

static ATTEMPTED_CATALOG_ROOTS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownloadMode {
    Off,
    On,
}

impl DownloadMode {
    fn from_env() -> Self {
        Self::from_env_value(std::env::var(DOWNLOAD_MODE_ENV).ok().as_deref())
    }

    fn from_env_value(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some(value) if value.eq_ignore_ascii_case("off") => Self::Off,
            _ => Self::On,
        }
    }
}

/// Attempt to acquire the exact generated production requested by analysis.
///
/// This function is suitable for registration with
/// `set_generated_production_acquisition_hook`. It returns successfully when
/// acquisition is disabled, because disabled downloading is an intentional
/// local-generation fallback. For every other path, only a verified catalog
/// lookup can turn the attempt into a hit.
pub fn acquire_generated_production(
    catalog: &SemanticPackCatalog,
    key: &GeneratedProductionKey,
) -> Result<(), String> {
    if DownloadMode::from_env() == DownloadMode::Off {
        return Ok(());
    }

    let catalog_root = canonical_catalog_root(catalog).map_err(|error| error.to_string())?;
    if !claim_catalog_attempt(catalog_root) {
        return Err("semantic-pack download was already attempted for this catalog".to_owned());
    }

    acquire_with_transport(catalog, key, &UreqTransport::new()).map_err(|error| error.to_string())
}

#[cfg(test)]
fn acquire_with_mode(
    catalog: &SemanticPackCatalog,
    key: &GeneratedProductionKey,
    mode: DownloadMode,
    transport: &dyn HttpTransport,
) -> Result<(), DownloadError> {
    if mode == DownloadMode::Off {
        return Ok(());
    }
    let catalog_root = canonical_catalog_root(catalog)?;
    if !claim_catalog_attempt(catalog_root) {
        return Err(DownloadError::new(
            "semantic-pack download was already attempted for this catalog",
        ));
    }
    acquire_with_transport(catalog, key, transport)
}

fn canonical_catalog_root(catalog: &SemanticPackCatalog) -> Result<PathBuf, DownloadError> {
    fs::canonicalize(catalog.root()).map_err(|error| {
        DownloadError::new(format!(
            "canonicalize semantic-pack catalog root {}: {error}",
            catalog.root().display()
        ))
    })
}

fn claim_catalog_attempt(root: PathBuf) -> bool {
    let attempted = ATTEMPTED_CATALOG_ROOTS.get_or_init(|| Mutex::new(HashSet::new()));
    attempted
        .lock()
        .expect("semantic-pack download attempt mutex poisoned")
        .insert(root)
}

trait HttpTransport {
    fn fetch(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>, DownloadError>;
}

struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .https_only(true)
            .max_redirects(MAX_REDIRECTS)
            .max_redirects_will_error(true)
            .timeout_global(Some(GLOBAL_TIMEOUT))
            .user_agent(format!("{USER_AGENT_PREFIX}/{RELEASE_VERSION}"))
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
        }
    }
}

impl HttpTransport for UreqTransport {
    fn fetch(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>, DownloadError> {
        let mut response = self
            .agent
            .get(url)
            .header("Accept", "application/octet-stream")
            .call()
            .map_err(|error| DownloadError::new(format!("GET {url}: {error}")))?;
        response
            .body_mut()
            .with_config()
            .limit(max_bytes)
            .read_to_vec()
            .map_err(|error| DownloadError::new(format!("read {url}: {error}")))
    }
}

fn acquire_with_transport(
    catalog: &SemanticPackCatalog,
    key: &GeneratedProductionKey,
    transport: &dyn HttpTransport,
) -> Result<(), DownloadError> {
    let archive_url = release_asset_url(ARCHIVE_NAME);
    let checksum_url = release_asset_url(CHECKSUM_NAME);
    let checksum = transport.fetch(&checksum_url, MAX_CHECKSUM_BYTES)?;
    let expected_digest = parse_checksum_sidecar(&checksum, ARCHIVE_NAME)?;
    // Use the same canonical identity as the process memoization. This keeps
    // equivalent catalog paths from creating separate download caches and
    // prevents a catalog-root symlink from redirecting the cache elsewhere.
    let catalog_root = canonical_catalog_root(catalog)?;
    let cache_dir = cache_dir(&catalog_root, &expected_digest);

    if cache_dir.exists() {
        install_verified_bundle(&cache_dir, catalog, key)?;
        return Ok(());
    }

    let archive = transport.fetch(&archive_url, MAX_ARCHIVE_BYTES)?;
    verify_digest(&archive, &expected_digest)?;

    let cache_parent = cache_dir
        .parent()
        .ok_or_else(|| DownloadError::new("semantic-pack cache has no parent directory"))?;
    fs::create_dir_all(cache_parent).map_err(|error| {
        DownloadError::new(format!(
            "create semantic-pack cache directory {}: {error}",
            cache_parent.display()
        ))
    })?;
    let temporary = TempDirBuilder::new()
        .prefix(".semantic-pack-download-")
        .tempdir_in(cache_parent)
        .map_err(|error| {
            DownloadError::new(format!("create semantic-pack staging directory: {error}"))
        })?;
    let bundle_root = safe_extract_archive(&archive, temporary.path())?;
    crate::release_bundle::verify_release_bundle(&bundle_root).map_err(|error| {
        DownloadError::new(format!("verify downloaded semantic-pack bundle: {error}"))
    })?;
    if let Err(error) = fs::rename(&bundle_root, &cache_dir) {
        // A concurrent process may have published the same content-addressed
        // directory between the existence check above and this rename. Unix
        // and Windows report that race with different io::ErrorKind values;
        // the immutable bundle verifier is authoritative for either case.
        if cache_dir.is_dir() {
            return install_verified_bundle(&cache_dir, catalog, key);
        }
        return Err(DownloadError::new(format!(
            "publish semantic-pack cache {}: {error}",
            cache_dir.display()
        )));
    }

    install_verified_bundle(&cache_dir, catalog, key)
}

fn release_asset_url(asset_name: &str) -> String {
    format!("https://github.com/{RELEASE_REPOSITORY}/releases/download/{RELEASE_TAG}/{asset_name}")
}

fn cache_dir(catalog_root: &Path, archive_digest: &str) -> PathBuf {
    catalog_root
        .join(DOWNLOAD_CACHE_DIR)
        .join(RELEASE_TAG)
        .join(archive_digest)
}

fn install_verified_bundle(
    bundle_root: &Path,
    catalog: &SemanticPackCatalog,
    key: &GeneratedProductionKey,
) -> Result<(), DownloadError> {
    crate::release_bundle::verify_release_bundle(bundle_root).map_err(|error| {
        DownloadError::new(format!("verify cached semantic-pack bundle: {error}"))
    })?;
    crate::release_bundle::install_release_bundle(bundle_root, catalog)
        .map_err(|error| DownloadError::new(format!("install semantic-pack bundle: {error}")))?;
    match catalog.generated_production(key).map_err(|error| {
        DownloadError::new(format!("check acquired generated production: {error}"))
    })? {
        Some(_) => Ok(()),
        None => Err(DownloadError::new(
            "verified semantic-pack bundle did not install the requested generated production",
        )),
    }
}

fn parse_checksum_sidecar(bytes: &[u8], expected_name: &str) -> Result<String, DownloadError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| DownloadError::new(format!("checksum sidecar is not UTF-8: {error}")))?;
    let mut lines = text.lines();
    let line = lines
        .next()
        .ok_or_else(|| DownloadError::new("checksum sidecar is empty"))?;
    if lines.next().is_some() {
        return Err(DownloadError::new(
            "checksum sidecar must contain exactly one line",
        ));
    }
    let (digest, name) = line
        .split_once("  ")
        .ok_or_else(|| DownloadError::new("checksum sidecar must use SHA256SUMS spacing"))?;
    if name != expected_name {
        return Err(DownloadError::new(format!(
            "checksum sidecar names {name:?}, expected {expected_name:?}"
        )));
    }
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DownloadError::new(
            "checksum sidecar does not contain a 64-character hexadecimal digest",
        ));
    }
    if digest.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(DownloadError::new(
            "checksum sidecar digest must use lowercase hexadecimal",
        ));
    }
    Ok(digest.to_owned())
}

fn verify_digest(bytes: &[u8], expected: &str) -> Result<(), DownloadError> {
    let actual = hex_digest(bytes);
    if actual == expected {
        Ok(())
    } else {
        Err(DownloadError::new(format!(
            "semantic-pack archive digest {actual} does not match sidecar {expected}"
        )))
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn safe_extract_archive(
    archive_bytes: &[u8],
    destination: &Path,
) -> Result<PathBuf, DownloadError> {
    let decoder = GzDecoder::new(archive_bytes);
    let mut archive = Archive::new(decoder);
    let mut seen = HashSet::new();
    let mut files = HashSet::new();
    let mut directories = HashSet::new();
    let mut extracted_bytes = 0_u64;
    let mut saw_top_level_directory = false;

    for entry in archive
        .entries()
        .map_err(|error| DownloadError::new(format!("read semantic-pack tar entries: {error}")))?
    {
        let mut entry = entry.map_err(|error| {
            DownloadError::new(format!("read semantic-pack tar entry: {error}"))
        })?;
        let path = entry
            .path()
            .map_err(|error| DownloadError::new(format!("read semantic-pack tar path: {error}")))?
            .into_owned();
        let relative = validate_archive_path(&path)?;
        if !seen.insert(relative.clone()) {
            return Err(DownloadError::new(format!(
                "semantic-pack archive contains duplicate path {}",
                relative.display()
            )));
        }
        let entry_type = entry.header().entry_type();
        let destination_path = destination.join(&relative);
        if relative == Path::new(EXPECTED_TOP_LEVEL) {
            if !entry_type.is_dir() {
                return Err(DownloadError::new(
                    "semantic-pack archive top-level entry is not a directory",
                ));
            }
            saw_top_level_directory = true;
        }
        match () {
            _ if entry_type.is_dir() => {
                reject_file_ancestor(&relative, &files)?;
                if !directories.insert(relative) {
                    return Err(DownloadError::new(
                        "semantic-pack archive contains duplicate directory",
                    ));
                }
                fs::create_dir_all(&destination_path).map_err(|error| {
                    DownloadError::new(format!(
                        "create extracted directory {}: {error}",
                        destination_path.display()
                    ))
                })?;
            }
            _ if entry_type.is_file() => {
                if relative == Path::new(EXPECTED_TOP_LEVEL) {
                    return Err(DownloadError::new(
                        "semantic-pack archive top-level entry is a file",
                    ));
                }
                reject_file_ancestor(&relative, &files)?;
                if directories.contains(&relative) {
                    return Err(DownloadError::new(format!(
                        "semantic-pack archive changes directory into a file: {}",
                        relative.display()
                    )));
                }
                let size = entry.header().size().map_err(|error| {
                    DownloadError::new(format!("read extracted file size: {error}"))
                })?;
                extracted_bytes = extracted_bytes
                    .checked_add(size)
                    .ok_or_else(|| DownloadError::new("semantic-pack extracted size overflow"))?;
                if extracted_bytes > MAX_EXTRACTED_BYTES {
                    return Err(DownloadError::new(
                        "semantic-pack extracted bytes exceed limit",
                    ));
                }
                if let Some(parent) = destination_path.parent() {
                    fs::create_dir_all(parent).map_err(|error| {
                        DownloadError::new(format!(
                            "create extracted parent directory {}: {error}",
                            parent.display()
                        ))
                    })?;
                }
                let mut output = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&destination_path)
                    .map_err(|error| {
                        DownloadError::new(format!(
                            "create extracted file {}: {error}",
                            destination_path.display()
                        ))
                    })?;
                let written = io::copy(&mut entry, &mut output).map_err(|error| {
                    DownloadError::new(format!(
                        "extract semantic-pack file {}: {error}",
                        relative.display()
                    ))
                })?;
                if written != size {
                    return Err(DownloadError::new(format!(
                        "semantic-pack file {} declared {size} bytes but extracted {written}",
                        relative.display()
                    )));
                }
                files.insert(relative);
            }
            _ => {
                return Err(DownloadError::new(format!(
                    "semantic-pack archive entry {} is not a regular file or directory",
                    relative.display()
                )));
            }
        }
    }
    if !saw_top_level_directory {
        return Err(DownloadError::new(format!(
            "semantic-pack archive must contain one {EXPECTED_TOP_LEVEL:?} top-level directory"
        )));
    }
    Ok(destination.join(EXPECTED_TOP_LEVEL))
}

fn validate_archive_path(path: &Path) -> Result<PathBuf, DownloadError> {
    let mut components = path.components();
    let top_level = match components.next() {
        Some(Component::Normal(component)) if component == OsStr::new(EXPECTED_TOP_LEVEL) => {
            component
        }
        Some(component) => {
            return Err(DownloadError::new(format!(
                "semantic-pack archive has invalid top-level path component {component:?}"
            )));
        }
        None => {
            return Err(DownloadError::new(
                "semantic-pack archive contains an empty path",
            ));
        }
    };
    let mut normalized = PathBuf::from(top_level);
    for component in components {
        match component {
            Component::Normal(component) => normalized.push(component),
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                return Err(DownloadError::new(format!(
                    "semantic-pack archive path contains traversal: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(normalized)
}

fn reject_file_ancestor(path: &Path, files: &HashSet<PathBuf>) -> Result<(), DownloadError> {
    let mut ancestor = path.parent();
    while let Some(candidate) = ancestor {
        if files.contains(candidate) {
            return Err(DownloadError::new(format!(
                "semantic-pack archive descends through file {}",
                candidate.display()
            )));
        }
        ancestor = candidate.parent();
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DownloadError(String);

impl DownloadError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl Display for DownloadError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for DownloadError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release_bundle::{
        PACK_SPEC_SCHEMA_VERSION, PinnedArtifact, PinnedJdkSourceLayout, PinnedLookupQuery,
        PinnedPackKind, PinnedPackSpec, generate_release_bundle,
    };
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        ActivationSelector, Compatibility, NameSelector, Provenance, Safety, VersionConstraint,
    };
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::collections::HashMap;
    use std::io::Write as _;
    use std::sync::Mutex;
    use tar::EntryType;
    use tempfile::tempdir;
    use zip::write::SimpleFileOptions;

    #[derive(Debug)]
    struct FakeTransport {
        responses: HashMap<String, Vec<u8>>,
        requests: Mutex<Vec<String>>,
    }

    impl FakeTransport {
        fn new(responses: HashMap<String, Vec<u8>>) -> Self {
            Self {
                responses,
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl HttpTransport for FakeTransport {
        fn fetch(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>, DownloadError> {
            self.requests
                .lock()
                .expect("fake transport mutex poisoned")
                .push(url.to_owned());
            let bytes = self
                .responses
                .get(url)
                .ok_or_else(|| DownloadError::new(format!("fake response missing for {url}")))?;
            if bytes.len() as u64 > max_bytes {
                return Err(DownloadError::new("fake response exceeds configured limit"));
            }
            Ok(bytes.clone())
        }
    }

    struct GeneratedBundleFixture {
        _directory: tempfile::TempDir,
        key: GeneratedProductionKey,
        archive: Vec<u8>,
    }

    #[derive(Clone, Copy)]
    enum Entry<'a> {
        Directory(&'a str),
        File(&'a str, &'a [u8]),
        Symlink(&'a str, &'a str),
    }

    fn tiny_archive(entries: &[Entry<'_>]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for entry in entries {
            let mut header = tar::Header::new_gnu();
            match entry {
                Entry::Directory(path) => {
                    header.set_entry_type(EntryType::dir());
                    header.set_size(0);
                    header.set_cksum();
                    builder.append_data(&mut header, path, io::empty()).unwrap();
                }
                Entry::File(path, bytes) => {
                    header.set_entry_type(EntryType::Regular);
                    header.set_size(bytes.len() as u64);
                    header.set_cksum();
                    builder.append_data(&mut header, path, *bytes).unwrap();
                }
                Entry::Symlink(path, target) => {
                    header.set_entry_type(EntryType::symlink());
                    header.set_size(0);
                    header.set_link_name(target).unwrap();
                    header.set_cksum();
                    builder.append_data(&mut header, path, io::empty()).unwrap();
                }
            }
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn write_zip(path: &Path, entries: &[(&str, &str)]) {
        let mut writer = zip::ZipWriter::new(fs::File::create(path).unwrap());
        for (entry_name, source) in entries {
            writer
                .start_file(*entry_name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(source.as_bytes()).unwrap();
        }
        writer.finish().unwrap();
    }

    fn archive_bundle(root: &Path) -> Vec<u8> {
        fn collect_files(root: &Path, current: &Path, files: &mut Vec<PathBuf>) {
            for entry in fs::read_dir(current).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    collect_files(root, &path, files);
                } else {
                    assert!(path.is_file(), "bundle contains a non-file entry");
                    files.push(path.strip_prefix(root).unwrap().to_owned());
                }
            }
        }

        let mut files = Vec::new();
        collect_files(root, root, &mut files);
        files.sort();
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut directory = tar::Header::new_gnu();
        directory.set_entry_type(EntryType::dir());
        directory.set_size(0);
        directory.set_cksum();
        builder
            .append_data(&mut directory, EXPECTED_TOP_LEVEL, io::empty())
            .unwrap();
        for relative in files {
            let path = root.join(&relative);
            let bytes = fs::read(path).unwrap();
            let archive_path = format!(
                "{EXPECTED_TOP_LEVEL}/{}",
                relative.to_string_lossy().replace('\\', "/")
            );
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(EntryType::Regular);
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            builder
                .append_data(&mut header, archive_path, bytes.as_slice())
                .unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn generated_bundle_fixture() -> GeneratedBundleFixture {
        let directory = tempdir().unwrap();
        let artifact = directory.path().join("src.zip");
        write_zip(
            &artifact,
            &[
                (
                    "java.base/module-info.java",
                    "module java.base { exports java.lang; }",
                ),
                (
                    "java.base/java/lang/Object.java",
                    "package java.lang; public class Object { public int hashCode() { return 0; } }",
                ),
            ],
        );
        fs::write(directory.path().join("NOTICE.txt"), "fixture notice\n").unwrap();
        let artifact_sha256 = hex_digest(&fs::read(&artifact).unwrap());
        let version = "21.0.8";
        let activation = ActivationSelector {
            package: None,
            module: None,
            toolchain: Some(NameSelector {
                name: "jdk".to_owned(),
                version: Some(format!("={version}")),
            }),
            targets: vec!["jvm".to_owned()],
            configurations: Vec::new(),
            artifact_sha256: None,
        };
        let pinned = PinnedPackSpec {
            schema_version: PACK_SPEC_SCHEMA_VERSION,
            pack_id: "bifrost.jdk".to_owned(),
            pack_version: version.to_owned(),
            ecosystem: "jdk".to_owned(),
            kind: PinnedPackKind::JdkSourceZip {
                layout: PinnedJdkSourceLayout::ModulePrefixed,
            },
            artifact: PinnedArtifact {
                file_name: "src.zip".to_owned(),
                sha256: artifact_sha256,
                url: Some("https://example.invalid/src.zip".to_owned()),
                container: None,
            },
            compatibility: Compatibility {
                bifrost: ">=0.8.18, <1.0.0".to_owned(),
                toolchains: vec![VersionConstraint {
                    name: "jdk".to_owned(),
                    requirement: format!("={version}"),
                }],
            },
            activation: vec![activation.clone()],
            provenance: Provenance {
                source: "fixture".to_owned(),
                revision: Some("fixture-v1".to_owned()),
            },
            license: "GPL-2.0-only WITH Classpath-exception-2.0".to_owned(),
            safety: Safety {
                generated_code_only: false,
                review_required: false,
            },
            notices: vec!["NOTICE.txt".to_owned()],
            measurement_activation: ActivationSelector {
                module: Some(NameSelector {
                    name: "java.base".to_owned(),
                    version: None,
                }),
                ..activation
            },
            measurement_queries: vec![PinnedLookupQuery::Type {
                name: "java.lang.Object".to_owned(),
            }],
        };
        let spec = directory.path().join("temurin-jdk.json");
        fs::write(&spec, serde_json::to_vec_pretty(&pinned).unwrap()).unwrap();
        let root = directory.path().join("bundle");
        let bundle = generate_release_bundle(
            &root,
            &[crate::release_bundle::BundleInput {
                spec_path: spec,
                artifact_path: artifact,
            }],
        )
        .unwrap();
        let generated = bundle.index.generated_productions.first().unwrap();
        let key = GeneratedProductionKey::new(
            generated.input_digest.clone(),
            generated.producer_name.clone(),
            generated.producer_version.clone(),
            generated.schema_version,
        )
        .unwrap();
        let archive = archive_bundle(&root);
        GeneratedBundleFixture {
            _directory: directory,
            key,
            archive,
        }
    }

    fn test_key() -> GeneratedProductionKey {
        GeneratedProductionKey::new(
            "0".repeat(64),
            "test-producer".to_owned(),
            "1.0.0".to_owned(),
            brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
        )
        .unwrap()
    }

    #[test]
    fn off_mode_makes_no_transport_calls_without_environment_mutation() {
        assert_eq!(
            DownloadMode::from_env_value(Some(" off ")),
            DownloadMode::Off
        );
        assert_eq!(DownloadMode::from_env_value(Some("on")), DownloadMode::On);
        let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
        let transport = FakeTransport::new(HashMap::new());
        acquire_with_mode(&catalog, &test_key(), DownloadMode::Off, &transport).unwrap();
        assert!(transport.requests.lock().unwrap().is_empty());
    }

    #[test]
    fn fake_transport_downloads_verifies_extracts_installs_and_caches_generated_bundle() {
        let fixture = generated_bundle_fixture();
        let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
        let archive_digest = hex_digest(&fixture.archive);
        let archive_url = release_asset_url(ARCHIVE_NAME);
        let checksum_url = release_asset_url(CHECKSUM_NAME);
        let checksum = format!("{archive_digest}  {ARCHIVE_NAME}\n").into_bytes();
        let transport = FakeTransport::new(HashMap::from([
            (checksum_url.clone(), checksum),
            (archive_url.clone(), fixture.archive.clone()),
        ]));

        acquire_with_mode(&catalog, &fixture.key, DownloadMode::On, &transport).unwrap();

        assert_eq!(
            transport.requests.lock().unwrap().as_slice(),
            &[checksum_url, archive_url]
        );
        assert!(
            catalog
                .generated_production(&fixture.key)
                .unwrap()
                .is_some()
        );
        let catalog_root = canonical_catalog_root(&catalog).unwrap();
        let cached = cache_dir(&catalog_root, &archive_digest);
        assert_eq!(
            cached,
            catalog_root
                .join(DOWNLOAD_CACHE_DIR)
                .join(RELEASE_TAG)
                .join(&archive_digest)
        );
        assert!(cached.join("index.json").is_file());
        assert!(cached.join("SHA256SUMS").is_file());
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn checksum_mismatch_does_not_install_requested_generated_production() {
        let fixture = generated_bundle_fixture();
        let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
        let archive_url = release_asset_url(ARCHIVE_NAME);
        let checksum_url = release_asset_url(CHECKSUM_NAME);
        let transport = FakeTransport::new(HashMap::from([
            (
                checksum_url,
                format!("{}  {ARCHIVE_NAME}\n", "0".repeat(64)).into_bytes(),
            ),
            (archive_url, fixture.archive.clone()),
        ]));
        assert!(acquire_with_mode(&catalog, &fixture.key, DownloadMode::On, &transport).is_err());
        assert!(
            catalog
                .generated_production(&fixture.key)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn corrupt_inner_bundle_does_not_install_requested_generated_production() {
        let fixture = generated_bundle_fixture();
        let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
        let archive = tiny_archive(&[
            Entry::Directory(EXPECTED_TOP_LEVEL),
            Entry::File("bifrost-semantic-packs/index.json", b"not-json"),
        ]);
        let archive_digest = hex_digest(&archive);
        let archive_url = release_asset_url(ARCHIVE_NAME);
        let checksum_url = release_asset_url(CHECKSUM_NAME);
        let transport = FakeTransport::new(HashMap::from([
            (
                checksum_url,
                format!("{archive_digest}  {ARCHIVE_NAME}\n").into_bytes(),
            ),
            (archive_url, archive),
        ]));
        assert!(acquire_with_mode(&catalog, &fixture.key, DownloadMode::On, &transport).is_err());
        assert!(
            catalog
                .generated_production(&fixture.key)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn fake_transport_records_bounded_requests() {
        let archive = tiny_archive(&[
            Entry::Directory(EXPECTED_TOP_LEVEL),
            Entry::File("bifrost-semantic-packs/index.json", b"{}"),
        ]);
        let url = release_asset_url(ARCHIVE_NAME);
        let transport = FakeTransport::new(HashMap::from([(url.clone(), archive.clone())]));
        assert_eq!(
            transport.fetch(&url, archive.len() as u64).unwrap(),
            archive
        );
        assert!(transport.fetch(&url, 1).is_err());
        assert_eq!(
            transport.requests.lock().unwrap().as_slice(),
            &[url.clone(), url]
        );
    }

    #[test]
    fn checksum_sidecar_requires_one_lowercase_named_digest() {
        let digest = "a".repeat(64);
        assert_eq!(
            parse_checksum_sidecar(
                format!("{digest}  {ARCHIVE_NAME}\n").as_bytes(),
                ARCHIVE_NAME
            )
            .unwrap(),
            digest
        );
        assert!(
            parse_checksum_sidecar(
                format!("{}  {ARCHIVE_NAME}\nextra\n", "a".repeat(64)).as_bytes(),
                ARCHIVE_NAME
            )
            .is_err()
        );
        assert!(
            parse_checksum_sidecar(
                format!("{}  other.tar.gz\n", "a".repeat(64)).as_bytes(),
                ARCHIVE_NAME
            )
            .is_err()
        );
        assert!(
            parse_checksum_sidecar(
                format!("{}  {ARCHIVE_NAME}\n", "A".repeat(64)).as_bytes(),
                ARCHIVE_NAME
            )
            .is_err()
        );
    }

    #[test]
    fn outer_archive_digest_is_strict() {
        let bytes = b"semantic-pack archive";
        let digest = hex_digest(bytes);
        assert!(verify_digest(bytes, &digest).is_ok());
        assert!(verify_digest(b"tampered", &digest).is_err());
    }

    #[test]
    fn safe_extraction_accepts_one_regular_bundle_tree() {
        let archive = tiny_archive(&[
            Entry::Directory(EXPECTED_TOP_LEVEL),
            Entry::Directory("bifrost-semantic-packs/nested"),
            Entry::File("bifrost-semantic-packs/nested/index.json", b"{}"),
        ]);
        let destination = tempfile::tempdir().unwrap();
        let root = safe_extract_archive(&archive, destination.path()).unwrap();
        assert_eq!(root, destination.path().join(EXPECTED_TOP_LEVEL));
        assert_eq!(fs::read(root.join("nested/index.json")).unwrap(), b"{}");
    }

    #[test]
    fn safe_extraction_rejects_traversal_and_links() {
        let destination = tempfile::tempdir().unwrap();
        assert!(validate_archive_path(Path::new("bifrost-semantic-packs/../escape")).is_err());

        let link = tiny_archive(&[
            Entry::Directory(EXPECTED_TOP_LEVEL),
            Entry::Symlink("bifrost-semantic-packs/link", "../escape"),
        ]);
        assert!(safe_extract_archive(&link, destination.path()).is_err());
    }
}
