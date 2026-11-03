//! Export selected JVM root decisions to the owning analyzer read capture.

use crate::analyzer::resolution::JvmSelectedRootPresence;
use crate::analyzer::store::resolution_operation::{
    ConsumedJvmRootPresence, SelectedResolutionOperation,
};
use crate::analyzer::{FactSubject, IAnalyzer, WorkspaceFactFamily};

pub fn record_consumed_root_presence(
    analyzer: &dyn IAnalyzer,
    operation: &SelectedResolutionOperation<'_, '_>,
) {
    record_root_presence_entries(analyzer, &operation.consumed_root_presence());
}

pub fn record_root_presence_entries(
    analyzer: &dyn IAnalyzer,
    entries: &[(String, JvmSelectedRootPresence)],
) {
    for (root, presence) in entries {
        analyzer.record_read(crate::analyzer::workspace_authority::workspace_fact_key(
            WorkspaceFactFamily::JvmSelectedRootPresence,
            FactSubject::Named {
                name: root.as_str().into(),
            },
            presence.read_digest(),
        ));
    }
}

pub struct RootPresenceExportGuard<'a> {
    pub analyzer: &'a dyn IAnalyzer,
    pub handle: Option<crate::analyzer::store::resolution_operation::JvmRootPresenceReadHandle>,
}

impl RootPresenceExportGuard<'_> {
    pub fn export_now(&mut self) {
        if let Some(handle) = self.handle.take() {
            let entries: ConsumedJvmRootPresence = handle.consumed();
            record_root_presence_entries(self.analyzer, &entries);
        }
    }
}

impl Drop for RootPresenceExportGuard<'_> {
    fn drop(&mut self) {
        self.export_now();
    }
}
