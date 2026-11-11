//! Currency for one selected reader and established main snapshot.

use brokk_bifrost_core::retention_budget::RetainedBytes;
use brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationRevision;

use super::resolution_selection::SelectedResolutionReadStamp;
use super::schema_lease::SchemaLease;

/// A validated lease on one reader's selected main snapshot. An unestablished
/// binding cannot certify a derivation. Attached databases, the semantic
/// catalog and models require independent proofs from the later capture slice.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReaderBinding {
    lease: Option<Lease>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Lease {
    reader_request: u64,
    transaction_epoch: u64,
    read_snapshot_epoch: u64,
    routing: [u8; 32],
    selection: [u8; 32],
    main_data_version: i64,
    schema: SchemaLease,
    unowned_changes: u64,
    total_changes: u64,
    scope: [u8; 32],
    stage: (u64, u64),
    main_only: bool,
}

impl ReaderBinding {
    pub fn unestablished() -> Self {
        Self { lease: None }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_lease(
        reader_request: u64,
        transaction_epoch: u64,
        read_snapshot_epoch: u64,
        routing: [u8; 32],
        selection: [u8; 32],
        stamp: SelectedResolutionReadStamp,
        schema: SchemaLease,
        total_changes: u64,
        scope: [u8; 32],
        stage: (u64, u64),
        current: bool,
        main_only: bool,
    ) -> Self {
        if !current {
            return Self::unestablished();
        }
        Self {
            lease: Some(Lease {
                reader_request,
                transaction_epoch,
                read_snapshot_epoch,
                routing,
                selection,
                main_data_version: stamp.main_data_version,
                schema,
                unowned_changes: stamp.unowned_changes,
                total_changes,
                scope,
                stage,
                main_only,
            }),
        }
    }

    /// True only for an unchanged, unscoped selection with no staged content.
    pub fn proves_main_selection(&self) -> bool {
        self.lease.as_ref().is_some_and(|lease| lease.main_only)
    }

    pub(crate) fn matches_declared_route_recipe(
        &self,
        routing: [u8; 32],
        selection: [u8; 32],
        scope: [u8; 32],
        stage: (u64, u64),
    ) -> bool {
        self.lease.as_ref().is_some_and(|lease| {
            lease.routing == routing
                && lease.selection == selection
                && lease.scope == scope
                && lease.stage == stage
                && lease.main_only
        })
    }

    /// True while `conn`'s schema is the one this binding was captured under.
    /// TEMP DDL inside an open transaction moves neither the transaction nor the
    /// snapshot epoch, so the epochs alone cannot say that a view a compute read
    /// through was redefined.
    pub(crate) fn matches_schema(
        &self,
        conn: &rusqlite::Connection,
        budget: &super::cache_budget::StoreCacheBudget,
    ) -> bool {
        self.lease
            .as_ref()
            .is_some_and(|lease| lease.schema.matches(conn, budget))
    }

    /// A pause ends the transaction even if a later resume recreates an
    /// otherwise equal selected snapshot. A scope or direct stage write inside
    /// the transaction changes what its reads see without ending it, so the
    /// scope and stage epochs must also be unchanged.
    pub(crate) fn matches_read_state(
        &self,
        reader_request: u64,
        transaction_epoch: u64,
        read_snapshot_epoch: u64,
        scope: [u8; 32],
        stage: (u64, u64),
    ) -> bool {
        self.lease.as_ref().is_some_and(|lease| {
            lease.reader_request == reader_request
                && lease.transaction_epoch == transaction_epoch
                && lease.read_snapshot_epoch == read_snapshot_epoch
                && lease.scope == scope
                && lease.stage == stage
        })
    }
}

impl DerivationRevision for ReaderBinding {
    fn is_established(&self) -> bool {
        self.lease.is_some()
    }
}

impl RetainedBytes for ReaderBinding {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}
