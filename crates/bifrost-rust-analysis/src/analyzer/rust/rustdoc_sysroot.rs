//! Production-only verification of compiler-distributed Rustdoc documents.
use std::collections::HashMap;
use std::io::{self, Cursor, Read};

use brokk_bifrost_core::analyzer::canonical_hash::{lower_hex_string, sha256_bytes};
use brokk_bifrost_semantic::analyzer::semantic_model::model::{
    RustSysrootProvenance, VerifiedSysrootReceipt,
};
use brokk_bifrost_semantic::analyzer::semantic_model::producer::{
    ArtifactProducerLimits, ExactArtifact,
};

/// No public constructor: a pin cannot manufacture this proof.
pub struct VerifiedSysrootDocuments {
    pub(super) receipts: Vec<VerifiedSysrootReceipt>,
    pub(super) source_digest: String,
}

struct DecompressedByteLimit<R> {
    inner: R,
    total: u64,
    limit: u64,
}

impl<R: Read> Read for DecompressedByteLimit<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.total += read as u64;
        if self.total > self.limit {
            return Err(io::Error::other(format!(
                "sysroot archive decompressed bytes {} exceed byte limit",
                self.total
            )));
        }
        Ok(read)
    }
}

impl VerifiedSysrootDocuments {
    /// Hash the actual compressed archive, then compare each selected document
    /// with its exact regular-file member. No archive content is executed.
    pub fn verify(
        archive: &[u8],
        artifact: &ExactArtifact,
        pins: &[(String, RustSysrootProvenance)],
        limits: &ArtifactProducerLimits,
    ) -> Result<Self, String> {
        if archive.len() as u64 > limits.max_artifact_bytes || pins.is_empty() {
            return Err("empty or oversized sysroot verification input".into());
        }
        if pins.iter().any(|(_, pin)| {
            !brokk_bifrost_semantic::analyzer::semantic_model::validate::is_canonical_relative_path(
                &pin.archive_member,
            )
        }) {
            return Err("sysroot archive member must be a canonical relative path".into());
        }
        let digest = lower_hex_string(&sha256_bytes(archive));
        if pins.iter().any(|(_, pin)| pin.archive_sha256 != digest) {
            return Err("sysroot archive digest mismatch".into());
        }
        if pins
            .iter()
            .any(|(_, pin)| !pin.toolchain.release_channel_is_consistent())
        {
            return Err("sysroot release and channel disagree".into());
        }
        let mut members = HashMap::new();
        let decoder = lzma_rust2::XzReader::new(Cursor::new(archive), false);
        let bounded = DecompressedByteLimit {
            inner: decoder,
            total: 0,
            limit: limits.max_artifact_bytes,
        };
        let mut tar = tar::Archive::new(bounded);
        for entry in tar.entries().map_err(|e| e.to_string())? {
            let mut entry = entry.map_err(|e| e.to_string())?;
            let path = entry
                .path()
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or("sysroot archive member is not UTF-8")?
                .to_owned();
            let wanted = pins.iter().any(|(_, pin)| pin.archive_member == path)
                || path.ends_with("/version")
                || path.ends_with("/git-commit-hash")
                || path.ends_with("/components");
            if !wanted {
                continue;
            }
            if !entry.header().entry_type().is_file() {
                return Err(format!("sysroot evidence is not a regular file: {path}"));
            }
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
            if members.insert(path, bytes).is_some() {
                return Err("duplicate archive evidence member".into());
            }
        }
        let mut receipts = Vec::new();
        for (path, pin) in pins {
            if pin.toolchain.commit.len() != 40
                || !pin.toolchain.commit.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err("invalid compiler commit".into());
            }
            let root = pin
                .archive_member
                .split('/')
                .next()
                .ok_or("missing archive root")?;
            let expected_member_prefix =
                format!("{root}/rust-docs-json-preview/share/doc/rust/json/");
            let name = pin
                .archive_member
                .strip_prefix(&expected_member_prefix)
                .and_then(|s| s.strip_suffix(".json"))
                .ok_or("invalid sysroot component member")?;
            if !matches!(name, "core" | "alloc" | "std" | "proc_macro" | "test") {
                return Err("crate is outside the proven sysroot set".into());
            }
            let metadata = |file: &str| -> Result<&str, String> {
                std::str::from_utf8(
                    members
                        .get(&format!("{root}/{file}"))
                        .ok_or_else(|| format!("missing {file}"))?,
                )
                .map(str::trim)
                .map_err(|e| e.to_string())
            };
            if metadata("git-commit-hash")? != pin.toolchain.commit
                || !metadata("components")?
                    .lines()
                    .any(|s| s == "rust-docs-json-preview")
            {
                return Err("sysroot compiler/component metadata mismatch".into());
            }
            let archive_version = metadata("version")?;
            if archive_version.split_whitespace().count() != 3 {
                return Err("archive version must identify compiler date and commit".into());
            }
            validate_version(archive_version, pin)?;
            let bytes = members
                .get(&pin.archive_member)
                .ok_or("missing sysroot member")?;
            let source = artifact
                .source_entries()
                .iter()
                .find(|s| s.relative_path() == path)
                .ok_or("missing selected sysroot document")?;
            if source.bytes() != bytes.as_slice() {
                return Err("sysroot document differs from archive member".into());
            }
            let doc: rustdoc_types::Crate =
                serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
            if doc.format_version != super::rustdoc_artifact::RUSTDOC_FORMAT_VERSION
                || doc.target.triple != pin.target
                || doc
                    .index
                    .get(&doc.root)
                    .and_then(|item| item.name.as_deref())
                    != Some(name)
            {
                return Err("sysroot document format/target/crate mismatch".into());
            }
            if let Some(version) = &doc.crate_version {
                validate_version(version, pin)?;
            }
            receipts.push(VerifiedSysrootReceipt {
                path: path.clone(),
                provenance: pin.clone(),
            });
        }
        receipts.sort_by(|a, b| a.path.cmp(&b.path));
        if receipts.windows(2).any(|p| p[0].path == p[1].path) {
            return Err("duplicate sysroot document".into());
        }
        Ok(Self {
            receipts,
            source_digest: artifact.sha256().to_owned(),
        })
    }
}

fn validate_version(value: &str, pin: &RustSysrootProvenance) -> Result<(), String> {
    let fields = value.split_whitespace().collect::<Vec<_>>();
    let release = &pin.toolchain.release;
    let consistent = match fields.as_slice() {
        [version] => *version == release.as_str(),
        [version, commit, date] => {
            *version == release.as_str()
                && commit
                    .strip_prefix('(')
                    .is_some_and(|c| c.len() >= 7 && pin.toolchain.commit.starts_with(c))
                && date.strip_suffix(')') == Some(pin.toolchain.date.as_str())
        }
        _ => false,
    };
    if !consistent {
        return Err("sysroot embedded toolchain version mismatch".into());
    }
    Ok(())
}
