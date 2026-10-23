//! Per-call access to the engine's thread-local resolution recorder.

pub trait ResolutionDiagnostics {
    fn recording(&self) -> bool;
    fn native_rejection_projection_active(&self) -> bool;
}

// Standalone store unit tests do not link the engine's thread-local recorder.
#[cfg(test)]
mod standalone_tests {
    struct TestResolutionDiagnostics;

    impl super::ResolutionDiagnostics for TestResolutionDiagnostics {
        fn recording(&self) -> bool {
            false
        }

        fn native_rejection_projection_active(&self) -> bool {
            false
        }
    }

    #[unsafe(no_mangle)]
    fn __brokk_bifrost_resolution_diagnostics_v1() -> &'static dyn super::ResolutionDiagnostics {
        &TestResolutionDiagnostics
    }
}
