//! Installer-owned first-party approval inventory production. Runtime never
//! needs the archive: the host pins the resulting inventory in launch argv.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use brokk_bifrost_analysis::analyzer::semantic_model::{
    FirstPartyApprovedManifest, FirstPartyApprovedRelease, FirstPartyApprovedShard,
    FirstPartyReleaseChannel, FirstPartyReleaseInventoryDocument,
};
use sha2::{Digest, Sha256};

use crate::release_bundle::{ReleaseAsset, ReleaseShard, verify_release_bundle_for_approval};

const MAX_RELEASE_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;

/// Generate from a release the host authenticated and is entitled to use.
/// Channel provenance is explicit; it is never inferred from pack names.
/// SHA-256 pins host-approved bytes, not an independent publisher signature.
/// No catalog or workspace configuration is opened or written.
pub fn prepare_first_party_approval_inventory(
    archive_path: &Path,
    archive_sha256: &str,
    channel: FirstPartyReleaseChannel,
    release_tag: &str,
) -> Result<FirstPartyReleaseInventoryDocument, String> {
    if !brokk_bifrost_analysis::analyzer::canonical_hash::is_lower_sha256(archive_sha256)
        || release_tag.trim().is_empty()
    {
        return Err(
            "approval inventory requires a release tag and lowercase archive SHA-256".into(),
        );
    }
    let file = File::open(archive_path)
        .map_err(|error| format!("open first-party release archive: {error}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_RELEASE_ARCHIVE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read first-party release archive: {error}"))?;
    if bytes.len() as u64 > MAX_RELEASE_ARCHIVE_BYTES {
        return Err("first-party release archive exceeds decode size".into());
    }
    let directory = tempfile::tempdir()
        .map_err(|error| format!("create private release verification directory: {error}"))?;
    let root = crate::download::extract_verified_approval_archive(
        &bytes,
        archive_sha256,
        directory.path(),
    )?;
    drop(bytes);
    let bundle = verify_release_bundle_for_approval(&root)
        .map_err(|error| format!("verify first-party release bundle: {error}"))?;
    let manifests = bundle
        .index
        .packs
        .iter()
        .map(|pack| {
            approved_manifest(
                &pack.manifest,
                &pack.manifest_content_sha256,
                &pack.manifest_semantic_sha256,
                &pack.shards,
            )
        })
        .chain(bundle.index.generated_productions.iter().map(|pack| {
            approved_manifest(
                &pack.manifest,
                &pack.manifest_content_sha256,
                &pack.manifest_semantic_sha256,
                &pack.shards,
            )
        }))
        .collect();
    FirstPartyReleaseInventoryDocument::new(vec![FirstPartyApprovedRelease {
        channel,
        repository: channel.repository().into(),
        tag: release_tag.into(),
        archive_sha256: archive_sha256.into(),
        manifests,
    }])
}

fn approved_manifest(
    object: &ReleaseAsset,
    content: &str,
    semantic: &str,
    shards: &[ReleaseShard],
) -> FirstPartyApprovedManifest {
    FirstPartyApprovedManifest {
        object_sha256: object.sha256.clone(),
        content_sha256: content.into(),
        semantic_sha256: semantic.into(),
        shards: shards
            .iter()
            .map(|shard| FirstPartyApprovedShard {
                shard_id: shard.shard_id.clone(),
                stored_sha256: shard.asset.sha256.clone(),
                content_sha256: shard.content_sha256.clone(),
                semantic_sha256: shard.semantic_sha256.clone(),
            })
            .collect(),
    }
}

/// Write once after complete verification. A failed generation cannot leave a
/// partial inventory that a later launch mistakes for an approved snapshot.
pub fn write_first_party_approval_inventory(
    output: &Path,
    document: &FirstPartyReleaseInventoryDocument,
) -> Result<String, String> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical = FirstPartyReleaseInventoryDocument::new(document.releases.clone())?;
    let mut bytes = serde_json::to_vec_pretty(&canonical).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    let digest = brokk_bifrost_analysis::analyzer::canonical_hash::lower_hex_string(
        &Sha256::digest(&bytes).into(),
    );
    if output.exists() {
        if fs::read(output).map_err(|error| error.to_string())? == bytes {
            return Ok(digest);
        }
        return Err("refusing to overwrite a different first-party approval inventory".into());
    }
    let mut file = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| format!("create approval inventory output: {error}"))?;
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.as_file()
        .sync_all()
        .map_err(|error| error.to_string())?;
    file.persist_noclobber(output)
        .map_err(|error| error.to_string())?;
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_pin_is_rejected_before_archive_extraction() {
        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join("release.tar.gz");
        fs::write(&archive, b"not an archive").unwrap();
        let error = prepare_first_party_approval_inventory(
            &archive,
            &"a".repeat(64),
            FirstPartyReleaseChannel::PublicSemanticPacks,
            "packs/v1",
        )
        .unwrap_err();
        assert!(error.contains("does not match"), "{error}");
    }

    #[test]
    fn output_is_deterministic_and_does_not_clobber_another_inventory() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("approval.json");
        let document = FirstPartyReleaseInventoryDocument::new(Vec::new()).unwrap();
        let first = write_first_party_approval_inventory(&output, &document).unwrap();
        assert_eq!(
            first,
            write_first_party_approval_inventory(&output, &document).unwrap()
        );
        fs::write(&output, b"customer content").unwrap();
        assert!(write_first_party_approval_inventory(&output, &document).is_err());
        assert_eq!(fs::read(output).unwrap(), b"customer content");
    }
}
