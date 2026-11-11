//! Trusted, offline binding of acquired docs.rs JSON to the existing Rust
//! dependency API evidence route. Acquisition itself belongs to the host.

use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{CargoMetadata, RustdocVersionEnvelope, decode_cargo_lockfile};
use brokk_bifrost_core::analyzer::config::{RustDependencyApiEvidence, RustPackageApiArtifact};

const MAX_ARCHIVE_BYTES: usize = 32 * 1024 * 1024;
const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_SOURCE_FILES: usize = 4096;
const MAX_RUSTDOC_BYTES: usize = 64 * 1024 * 1024;

/// A trusted host's record of one exact docs.rs build and the matching
/// crates.io archive. Paths are already acquired; this adapter never networks
/// or runs Cargo, rustdoc, build scripts, or crate code.
#[derive(Debug, Clone)]
pub struct DocsRsArtifactInput {
    pub package_id: String,
    pub crate_name: String,
    pub crate_archive_path: PathBuf,
    pub crate_archive_sha256: String,
    pub rustdoc_json_path: PathBuf,
    pub rustdoc_json_sha256: String,
    /// Fully resolved features recorded for the docs.rs build, not merely its
    /// `package.metadata.docs.rs.features` request.
    pub docsrs_resolved_features: Vec<String>,
    pub rustdoc_toolchain: String,
    pub rustdoc_format_version: u32,
    /// Exact format-pinned docs.rs URL from which the trusted host acquired
    /// `rustdoc_json_path` before decompression and SHA-256 verification.
    pub docsrs_url: String,
    pub target: String,
    pub docsrs_cfg: bool,
    pub authority: DocsRsAuthority,
}

/// The offline selection decision. M3a admits exact artifacts only; the
/// follow-up converter/selection milestone will consume approximate records.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DocsRsAuthority {
    Exact,
    Approximate {
        resolved_version: String,
        built_from_version: String,
        mismatch_kinds: Vec<String>,
        direction: String,
        selection_rule_id: String,
        selection_rule_version: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DocsRsBindingRow {
    pub package_id: String,
    pub crate_name: String,
    pub crate_archive_sha256: String,
    pub rustdoc_json_sha256: String,
    pub rustdoc_toolchain: String,
    pub rustdoc_format_version: u32,
    pub docsrs_url: String,
    pub target: String,
    pub docsrs_cfg: bool,
    pub docsrs_resolved_features: Vec<String>,
    pub authority: DocsRsAuthority,
    pub status: String,
}

#[derive(Debug)]
pub struct DocsRsBindingOutcome {
    pub evidence: RustDependencyApiEvidence,
    pub rows: Vec<DocsRsBindingRow>,
}

/// Fill the existing configured evidence route. Every input gets one stable
/// ledger decision; only proved artifacts enter `evidence.packages`. The host
/// must retain the exact JSON/archive bytes and the independent docs.rs build
/// record that supplied `docsrs_resolved_features` and toolchain.
pub fn bind_docsrs_artifacts(
    mut evidence: RustDependencyApiEvidence,
    inputs: &[DocsRsArtifactInput],
) -> Result<DocsRsBindingOutcome, String> {
    if !evidence.packages.is_empty() {
        return Err("docs.rs binding requires an empty package list".into());
    }
    if !evidence.metadata_path.is_absolute() || !evidence.lockfile_path.is_absolute() {
        return Err("docs.rs binding requires absolute evidence paths".into());
    }
    let metadata_bytes = read_bounded(&evidence.metadata_path, MAX_RUSTDOC_BYTES)?;
    let metadata: CargoMetadata = serde_json::from_slice(&metadata_bytes)
        .map_err(|error| format!("invalid Cargo metadata: {error}"))?;
    let lock_bytes = read_bounded(&evidence.lockfile_path, MAX_RUSTDOC_BYTES)?;
    let lock_text = std::str::from_utf8(&lock_bytes).map_err(|error| error.to_string())?;
    let lock = decode_cargo_lockfile(lock_text, &evidence.lockfile_path)
        .map_err(|error| format!("invalid Cargo.lock: {error:?}"))?;
    let mut rows = Vec::with_capacity(inputs.len());
    let mut seen = std::collections::HashSet::new();
    for input in inputs {
        let mut features = input.docsrs_resolved_features.clone();
        features.sort();
        features.dedup();
        let status = if !seen.insert((input.package_id.clone(), input.crate_name.clone())) {
            Err("duplicate package/crate binding".to_owned())
        } else {
            validate_one(input, &features, &metadata, &lock, &evidence)
        };
        if status.is_ok() {
            evidence.packages.push(RustPackageApiArtifact {
                package_id: input.package_id.clone(),
                crate_name: input.crate_name.clone(),
                enabled_features: features.clone(),
                rustdoc_json_path: input.rustdoc_json_path.clone(),
                rustdoc_toolchain: input.rustdoc_toolchain.clone(),
                rustdoc_format_version: input.rustdoc_format_version,
                rustdoc_cfgs: vec!["docsrs".to_owned()],
                approximation: None,
            });
        }
        rows.push(DocsRsBindingRow {
            package_id: input.package_id.clone(),
            crate_name: input.crate_name.clone(),
            crate_archive_sha256: input.crate_archive_sha256.clone(),
            rustdoc_json_sha256: input.rustdoc_json_sha256.clone(),
            rustdoc_toolchain: input.rustdoc_toolchain.clone(),
            rustdoc_format_version: input.rustdoc_format_version,
            docsrs_url: input.docsrs_url.clone(),
            target: input.target.clone(),
            docsrs_cfg: input.docsrs_cfg,
            docsrs_resolved_features: features,
            authority: input.authority.clone(),
            status: status
                .map(|()| "admitted".to_owned())
                .unwrap_or_else(|reason| format!("missing_declaration_evidence:{reason}")),
        });
    }
    rows.sort_by(|a, b| (&a.package_id, &a.crate_name).cmp(&(&b.package_id, &b.crate_name)));
    evidence
        .packages
        .sort_by(|a, b| (&a.package_id, &a.crate_name).cmp(&(&b.package_id, &b.crate_name)));
    Ok(DocsRsBindingOutcome { evidence, rows })
}

fn validate_one(
    input: &DocsRsArtifactInput,
    features: &[String],
    metadata: &CargoMetadata,
    lock: &super::CargoLockfile,
    evidence: &RustDependencyApiEvidence,
) -> Result<(), String> {
    if input.authority != DocsRsAuthority::Exact {
        return Err(
            "approximate authority awaits version-selection and converter milestone".into(),
        );
    }
    if !input.crate_archive_path.is_absolute() || !input.rustdoc_json_path.is_absolute() {
        return Err("docs.rs binding requires absolute artifact paths".into());
    }
    if !input.docsrs_cfg || input.rustdoc_toolchain.trim().is_empty() {
        return Err("missing docsrs cfg or exact toolchain".into());
    }
    if input.rustdoc_format_version != rustdoc_types::FORMAT_VERSION {
        return Err("unsupported rustdoc format version".into());
    }
    if input.target != evidence.target {
        return Err("target mismatch".into());
    }
    let package = metadata
        .packages
        .iter()
        .find(|p| p.id == input.package_id)
        .ok_or("package missing from Cargo metadata")?;
    let expected_url = format!(
        "https://docs.rs/crate/{}/{}/json/{}.gz",
        package.name, package.version, input.rustdoc_format_version
    );
    if input.docsrs_url != expected_url {
        return Err("docs.rs URL is not the exact version/format endpoint".into());
    }
    let node = metadata
        .resolve
        .as_ref()
        .and_then(|r| r.nodes.iter().find(|n| n.id == input.package_id))
        .ok_or("package missing from Cargo resolve")?;
    let mut selected = node.features.clone();
    selected.sort();
    selected.dedup();
    if features != selected {
        return Err("docs.rs feature set differs from Cargo-resolved features".into());
    }
    if !package.targets.iter().any(|t| {
        t.name.replace('-', "_") == input.crate_name.replace('-', "_")
            && t.kind.iter().any(|k| k == "lib" || k == "proc-macro")
    }) {
        return Err("crate is not a selected package library target".into());
    }
    let locked = lock
        .packages
        .iter()
        .find(|p| {
            p.name == package.name && p.version == package.version && p.source == package.source
        })
        .ok_or("package missing from Cargo.lock")?;
    let archive = read_bounded(&input.crate_archive_path, MAX_ARCHIVE_BYTES)?;
    check_hash(&archive, &input.crate_archive_sha256)?;
    if locked.checksum.as_deref() != Some(input.crate_archive_sha256.as_str()) {
        return Err("crate archive hash differs from Cargo.lock checksum".into());
    }
    inspect_source_archive(&archive, &package.name, &package.version, features)?;
    let json = read_bounded(&input.rustdoc_json_path, MAX_RUSTDOC_BYTES)?;
    check_hash(&json, &input.rustdoc_json_sha256)?;
    let envelope: RustdocVersionEnvelope =
        serde_json::from_slice(&json).map_err(|error| format!("invalid rustdoc JSON: {error}"))?;
    if envelope.format_version != rustdoc_types::FORMAT_VERSION
        || envelope.crate_version.as_deref() != Some(package.version.as_str())
        || envelope.target.as_ref().map(|t| t.triple.as_str()) != Some(evidence.target.as_str())
    {
        return Err("rustdoc format, version or target differs from selected package".into());
    }
    Ok(())
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let file = fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > limit {
        return Err(format!("{} exceeds byte limit", path.display()));
    }
    Ok(bytes)
}

fn check_hash(bytes: &[u8], expected: &str) -> Result<(), String> {
    let actual = brokk_bifrost_core::analyzer::canonical_hash::lower_hex_string(
        &Sha256::digest(bytes).into(),
    );
    if actual != expected {
        return Err("SHA-256 mismatch".into());
    }
    Ok(())
}

fn inspect_source_archive(
    bytes: &[u8],
    name: &str,
    version: &str,
    features: &[String],
) -> Result<(), String> {
    let mut archive = tar::Archive::new(GzDecoder::new(Cursor::new(bytes)));
    let mut manifest = false;
    let mut source_files = 0;
    let mut source_bytes = 0_u64;
    for entry in archive.entries().map_err(|error| error.to_string())? {
        let mut entry = entry.map_err(|error| error.to_string())?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path().map_err(|error| error.to_string())?;
        let path = path.to_string_lossy().to_string();
        if !path.starts_with(&format!("{name}-{version}/")) {
            return Err("archive root mismatch".into());
        }
        if path.split('/').any(|component| component == "..") {
            return Err("archive path traversal".into());
        }
        if path.ends_with("/Cargo.toml.orig") || (path.ends_with("/Cargo.toml") && !manifest) {
            let mut text = String::new();
            entry
                .take(MAX_SOURCE_BYTES + 1)
                .read_to_string(&mut text)
                .map_err(|error| error.to_string())?;
            if text.len() as u64 > MAX_SOURCE_BYTES {
                return Err("manifest exceeds byte limit".into());
            }
            let value: toml::Value = toml::from_str(&text)
                .map_err(|error| format!("invalid crate manifest: {error}"))?;
            if value
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(toml::Value::as_str)
                != Some(name)
                || value
                    .get("package")
                    .and_then(|p| p.get("version"))
                    .and_then(toml::Value::as_str)
                    != Some(version)
            {
                return Err("archive manifest identity mismatch".into());
            }
            if value
                .get("package")
                .and_then(|p| p.get("build"))
                .is_some_and(|build| build.as_bool() != Some(false))
            {
                return Err("build script requires independent cfg audit".into());
            }
            let docs = value
                .get("package")
                .and_then(|p| p.get("metadata"))
                .and_then(|m| m.get("docs"))
                .and_then(|d| d.get("rs"));
            if let Some(requested) = docs
                .and_then(|d| d.get("features"))
                .and_then(toml::Value::as_array)
            {
                for feature in requested {
                    let feature = feature.as_str().ok_or("non-string docs.rs feature")?;
                    if !features.iter().any(|selected| selected == feature) {
                        return Err("docs.rs requested feature absent from resolved set".into());
                    }
                }
            }
            if docs
                .and_then(|d| d.get("all-features"))
                .and_then(toml::Value::as_bool)
                == Some(true)
                && let Some(all) = value.get("features").and_then(toml::Value::as_table)
            {
                for feature in all.keys() {
                    if !features.iter().any(|selected| selected == feature) {
                        return Err("docs.rs all-features build differs from resolved set".into());
                    }
                }
            }
            manifest = true;
        } else if path.ends_with(".rs") {
            source_files += 1;
            source_bytes = source_bytes.saturating_add(entry.size());
            if source_files > MAX_SOURCE_FILES
                || entry.size() > MAX_SOURCE_BYTES
                || source_bytes > MAX_RUSTDOC_BYTES as u64
            {
                return Err("source archive exceeds scan limits".into());
            }
            if path.ends_with("/build.rs") {
                return Err("build script requires independent cfg audit".into());
            }
            let mut text = String::new();
            entry
                .read_to_string(&mut text)
                .map_err(|error| error.to_string())?;
            scan_rust_source(&text)?;
        }
    }
    if !manifest || source_files == 0 {
        return Err("archive lacks manifest or Rust source".into());
    }
    Ok(())
}

fn scan_rust_source(source: &str) -> Result<(), String> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .map_err(|error| error.to_string())?;
    let tree = parser
        .parse(source, None)
        .ok_or("Rust syntax parse failed")?;
    if tree.root_node().has_error() {
        return Err("Rust source has unparsed syntax; docsrs cfg exclusion is unproved".into());
    }
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        // Macro bodies are opaque token trees to tree-sitter. A macro may emit
        // an item-level cfg, or `cfg!(docsrs)` may choose a different API, so
        // no declaration equivalence can be proved if either flag occurs here.
        let mut parent = node.parent();
        let mut inside_attribute = false;
        while let Some(ancestor) = parent {
            if matches!(ancestor.kind(), "attribute_item" | "inner_attribute_item") {
                inside_attribute = true;
                break;
            }
            parent = ancestor.parent();
        }
        if node.kind() == "token_tree" && !inside_attribute {
            let text = node
                .utf8_text(source.as_bytes())
                .map_err(|error| error.to_string())?;
            if text.contains("docsrs") || text.contains("DOCS_RS") {
                return Err("macro token tree may change docs.rs public API".into());
            }
        }
        if node.kind() == "attribute_item" || node.kind() == "inner_attribute_item" {
            let text = node
                .utf8_text(source.as_bytes())
                .map_err(|error| error.to_string())?;
            let compact = text
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>();
            let harmless_doc_cfg = compact.starts_with("#[cfg_attr(docsrs,doc(cfg(")
                && compact.ends_with(")))]")
                && compact.matches("cfg(").count() == 1;
            if compact.contains("docsrs") && !harmless_doc_cfg {
                return Err("source has item-gating docsrs cfg".into());
            }
        }
        // A custom build script is rejected above. Also reject source-level
        // references to the docs.rs build flag on this exact source set.
        if node.kind() == "string_literal" {
            let text = node
                .utf8_text(source.as_bytes())
                .map_err(|error| error.to_string())?;
            if text.contains("DOCS_RS") {
                return Err("build script observes DOCS_RS".into());
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::scan_rust_source;

    #[test]
    fn docsrs_source_gate_rejects_item_cfg_and_build_script_observation() {
        assert!(scan_rust_source("#[cfg(docsrs)] pub fn only_in_docs() {}\n").is_err());
        assert!(scan_rust_source("#[cfg(not(docsrs))] pub fn absent_in_docs() {}\n").is_err());
        assert!(scan_rust_source("fn main() { let _ = std::env::var(\"DOCS_RS\"); }\n").is_err());
        assert!(
            scan_rust_source(
                "cfg_if::cfg_if! { if #[cfg(docsrs)] { pub fn only_in_docs() {} } }\n"
            )
            .is_err()
        );
        assert!(
            scan_rust_source(
                "macro_rules! m { () => { #[cfg(docsrs)] pub fn only_in_docs() {} } }\n"
            )
            .is_err()
        );
        assert!(scan_rust_source("fn f() { if cfg!(docsrs) { use_doc_api(); } }\n").is_err());
        assert!(scan_rust_source("fn f() { let _ = env!(\"DOCS_RS\"); }\n").is_err());
        assert!(
            scan_rust_source("#[cfg_attr(docsrs, doc(cfg(feature = \"x\")))] pub fn stable() {}\n")
                .is_ok()
        );
        assert!(scan_rust_source("#[cfg_attr(docsrs, doc(cfg(feature = \"x\")), cfg(feature = \"y\"))] pub fn unstable() {}\n").is_err());
    }
}
