use super::*;

#[doc(hidden)]
pub fn completed_topology(build: DirectImportTopologyBuild) -> DirectImportTopology {
    assert!(build.fallback.is_none());
    match build.outcome {
        DerivedLayerBuildOutcome::Complete {
            layer: DerivedLayer::DirectImportTopology(topology),
            ..
        } => topology,
        DerivedLayerBuildOutcome::Cancelled { .. }
        | DerivedLayerBuildOutcome::Unavailable { .. } => {
            panic!("expected complete direct import topology")
        }
    }
}

#[doc(hidden)]
pub fn generous_limits() -> DirectImportTopologyLimits {
    DirectImportTopologyLimits {
        max_files: 100,
        max_edges: 100,
        max_retained_bytes: 1024 * 1024,
    }
}
