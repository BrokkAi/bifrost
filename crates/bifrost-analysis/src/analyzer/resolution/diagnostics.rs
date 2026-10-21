//! Per-call access to the engine's thread-local resolution recorder.

pub trait ResolutionDiagnostics {
    fn recording(&self) -> bool;
    fn native_rejection_projection_active(&self) -> bool;
}
