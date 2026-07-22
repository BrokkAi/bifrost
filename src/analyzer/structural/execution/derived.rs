use serde::{Serialize, Serializer};

use crate::analyzer::semantic::ids::StableDigest;

/// The semantic family of one reusable, immutable query-execution layer.
///
/// A runtime layer owner must define its complete validity key next to its
/// materializer. See `CompleteValueCache` for the required key dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DerivedLayerKind {
    DirectImportTopology,
}

/// The plan-known shape of a reusable value requested by one physical query
/// operator.
///
/// This is deliberately not a bound cache key: physical selection has no
/// analyzer snapshot or runtime resolver configuration. If a concrete layer is
/// promoted, its owner must combine this request with those identities before
/// acquiring the generic complete-value cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub(crate) struct DerivedLayerRequest {
    kind: DerivedLayerKind,
    #[serde(serialize_with = "serialize_stable_digest")]
    projection_filter_fingerprint: StableDigest,
    representation_version: u32,
}

impl DerivedLayerRequest {
    const DIRECT_IMPORT_TOPOLOGY_REPRESENTATION_VERSION: u32 = 1;
    const COMPLETE_DIRECT_IMPORT_TOPOLOGY_REQUEST: &[u8] =
        b"bifrost-derived-layer:direct-import-topology:complete:no-filter";

    /// Request the complete project-local direct import topology.
    ///
    /// Reverse import traversal needs this complete relation. Forward import
    /// traversal is frontier-dependent and therefore does not use this request.
    pub(crate) fn complete_direct_import_topology() -> Self {
        Self {
            kind: DerivedLayerKind::DirectImportTopology,
            projection_filter_fingerprint: StableDigest::sha256(
                Self::COMPLETE_DIRECT_IMPORT_TOPOLOGY_REQUEST,
            ),
            representation_version: Self::DIRECT_IMPORT_TOPOLOGY_REPRESENTATION_VERSION,
        }
    }
}

fn serialize_stable_digest<S>(digest: &StableDigest, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&digest.to_string())
}
