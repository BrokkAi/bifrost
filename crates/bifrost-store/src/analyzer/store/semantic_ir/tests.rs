//! Round-trip differential: lower real Rust files, store the rows, read them
//! back, and require the rebuilt artifact to be the lowered one.

use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

use crate::analyzer::store::AnalyzerStore;
use crate::analyzer::store::planner_statistics::pinned_plans::{explain_pin, pinned};

/// The head lookup seeks the blob by its identity and the head and the epoch
/// by their keys, with and without representative statistics.
#[test]
fn semantic_ir_publication_lookup_seeks_keys() {
    for state in PlannerStatisticsState::BOTH {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        state.install(&conn);
        let plan = explain_pin(&conn, &pinned("semantic_ir_publication"));
        for (table, access) in [
            ("blobs", "sqlite_autoindex_blobs_1"),
            ("publications", "PRIMARY KEY"),
            ("epochs", "PRIMARY KEY"),
        ] {
            assert!(
                plan.iter().any(|detail| {
                    detail.starts_with(&format!("SEARCH {table} ")) && detail.contains(access)
                }),
                "{state}: {table} is not searched by {access}: {plan:#?}"
            );
        }
        for forbidden in ["SCAN", "AUTOMATIC", "TEMP B-TREE", "CO-ROUTINE"] {
            assert!(
                plan.iter().all(|detail| !detail.contains(forbidden)),
                "{state}: the plan uses {forbidden}: {plan:#?}"
            );
        }
    }
}
