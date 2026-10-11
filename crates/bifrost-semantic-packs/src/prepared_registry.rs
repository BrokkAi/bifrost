//! Explicit, byte-exact selection of the frozen transition registry.
//!
//! This is not a qualified external release bundle. It retains the registry's
//! session provenance and partial completeness without inventing extraction
//! accounting. Retirement follows the external-content migration (#4438).

use std::fs;
use std::io;
use std::path::Path;

use brokk_bifrost_analysis::analyzer::semantic_model::{
    ArtifactEncoding, DecodeLimits, SemanticPackCatalog, SessionPackSource, SessionPackSourceKind,
    write_compiled_semantic_model_pack,
};
use serde::{Deserialize, Serialize};

use crate::{BIFROST_EMBEDDED_PACKS, EmbeddedPackRegistration, EmbeddedSemanticPack};

pub const PREPARED_REGISTRY_MARKER: &str = "embedded-registry.json";

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrySelection {
    schema_version: u32,
    sources: Vec<String>,
}

fn current_selection() -> RegistrySelection {
    RegistrySelection {
        schema_version: 1,
        sources: BIFROST_EMBEDDED_PACKS
            .packs()
            .iter()
            .map(|pack| pack.source_id().to_owned())
            .collect(),
    }
}

/// Prepare all registered packs, with the selection marker written last.
/// Identical output is reusable; different compiled bytes are rejected.
pub fn export_embedded_registry(root: &Path) -> io::Result<()> {
    for (position, pack) in BIFROST_EMBEDDED_PACKS.packs().iter().enumerate() {
        let compiled = pack
            .decode(&DecodeLimits::default())
            .map_err(io::Error::other)?;
        write_compiled_semantic_model_pack(&root.join(position.to_string()), &compiled)?;
    }
    fs::write(
        root.join(PREPARED_REGISTRY_MARKER),
        serde_json::to_vec_pretty(&current_selection())?,
    )
}

/// Read and validate the complete explicit selection before catalog mutation.
/// Every byte must match this engine's registry; no absent or invalid selected
/// pack can be replaced by a pack from the binary.
pub fn register_prepared_registry(
    root: &Path,
    catalog: &SemanticPackCatalog,
) -> io::Result<Vec<EmbeddedPackRegistration>> {
    let selection: RegistrySelection =
        serde_json::from_slice(&fs::read(root.join(PREPARED_REGISTRY_MARKER))?)?;
    if selection != current_selection() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("prepared semantic registry selection differs from this engine: {selection:?}"),
        ));
    }
    let limits = DecodeLimits::default();
    let decoded = BIFROST_EMBEDDED_PACKS
        .packs()
        .iter()
        .enumerate()
        .map(|(position, expected)| {
            let directory = root.join(position.to_string());
            let manifest_bytes = fs::read(directory.join("manifest.json"))?;
            if manifest_bytes != expected.manifest_bytes() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "prepared semantic manifest differs: {}",
                        expected.source_id()
                    ),
                ));
            }
            // Decode the trusted manifest to derive paths, rather than using
            // paths from an unverified caller-controlled manifest.
            let manifest = brokk_bifrost_analysis::analyzer::semantic_model::decode_manifest(
                &manifest_bytes,
                &limits,
            )
            .map_err(io::Error::other)?;
            let shards = manifest
                .shards
                .iter()
                .zip(expected.shard_bytes)
                .map(|(descriptor, expected_bytes)| {
                    let extension = match descriptor.encoding {
                        ArtifactEncoding::Raw => "json",
                        ArtifactEncoding::Deflate => "deflate",
                    };
                    let file = directory
                        .join("shards")
                        .join(format!("{}.{}", descriptor.shard_id, extension));
                    let bytes = fs::read(&file)?;
                    if bytes != *expected_bytes {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("prepared semantic shard differs: {}", file.display()),
                        ));
                    }
                    Ok(bytes)
                })
                .collect::<io::Result<Vec<_>>>()?;
            let shard_bytes = shards.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let prepared =
                EmbeddedSemanticPack::new(expected.source_id(), &manifest_bytes, &shard_bytes);
            let compiled = prepared.decode(&limits).map_err(io::Error::other)?;
            Ok((expected.source_id(), compiled))
        })
        .collect::<io::Result<Vec<_>>>()?;
    decoded
        .iter()
        .map(|(source_id, compiled)| {
            let manifest_digest = catalog
                .register_session_pack(
                    compiled,
                    &SessionPackSource {
                        kind: SessionPackSourceKind::Embedded,
                        source_id: (*source_id).to_owned(),
                    },
                )
                .map_err(io::Error::other)?;
            Ok(EmbeddedPackRegistration {
                source_id: (*source_id).to_owned(),
                manifest_digest,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::semantic_model::CatalogOptions;

    #[test]
    fn full_prepared_selection_matches_direct_registry_and_rejects_corruption() {
        let output = tempfile::tempdir().unwrap();
        export_embedded_registry(output.path()).unwrap();
        export_embedded_registry(output.path()).unwrap();
        let direct = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let prepared = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        assert_eq!(
            register_prepared_registry(output.path(), &prepared).unwrap(),
            BIFROST_EMBEDDED_PACKS
                .register_all(&direct, &DecodeLimits::default())
                .unwrap(),
        );
        assert_eq!(
            prepared.inventory_bounded(100).unwrap(),
            direct.inventory_bounded(100).unwrap()
        );
        let invalid_catalog =
            SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let rust_position = BIFROST_EMBEDDED_PACKS
            .packs()
            .iter()
            .position(|pack| {
                pack.decode(&DecodeLimits::default())
                    .unwrap()
                    .manifest
                    .language
                    == "rust"
            })
            .expect("full registry includes Rust models");
        let manifest = output
            .path()
            .join(rust_position.to_string())
            .join("manifest.json");
        let original = fs::read(&manifest).unwrap();
        fs::write(&manifest, b"{}").unwrap();
        assert!(register_prepared_registry(output.path(), &invalid_catalog).is_err());
        assert!(
            invalid_catalog
                .inventory_bounded(100)
                .unwrap()
                .packs
                .is_empty()
        );
        fs::write(&manifest, original).unwrap();
        let selection_file = output.path().join(PREPARED_REGISTRY_MARKER);
        let mut selection = current_selection();
        selection.sources.pop();
        fs::write(&selection_file, serde_json::to_vec(&selection).unwrap()).unwrap();
        assert!(register_prepared_registry(output.path(), &invalid_catalog).is_err());
        assert!(
            invalid_catalog
                .inventory_bounded(100)
                .unwrap()
                .packs
                .is_empty()
        );
        export_embedded_registry(output.path()).unwrap();
        let compiled = BIFROST_EMBEDDED_PACKS.packs()[rust_position]
            .decode(&DecodeLimits::default())
            .unwrap();
        let shard = &compiled.shards[0].descriptor;
        let extension = match shard.encoding {
            ArtifactEncoding::Raw => "json",
            ArtifactEncoding::Deflate => "deflate",
        };
        fs::remove_file(
            output
                .path()
                .join(rust_position.to_string())
                .join("shards")
                .join(format!("{}.{}", shard.shard_id, extension)),
        )
        .unwrap();
        assert!(register_prepared_registry(output.path(), &invalid_catalog).is_err());
        assert!(
            invalid_catalog
                .inventory_bounded(100)
                .unwrap()
                .packs
                .is_empty()
        );
    }
}
