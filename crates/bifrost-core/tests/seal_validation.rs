//! Exercise the library without cfg(test), including the process-local override.

use brokk_bifrost_core::cache_db::{open_unified_connection, seal_validates};

#[test]
fn production_writer_seals_with_registered_validation() {
    let dir = tempfile::tempdir().unwrap();
    let conn = open_unified_connection(&dir.path().join("seal.db")).unwrap();
    conn.execute_batch(
        "INSERT INTO blobs(id, blob_oid, lang, generation)
           VALUES(64, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'go', 0);
         INSERT INTO resolution_fragment_interiors(
           blob_id, lang, semantic_language, producer_epoch, interior_digest,
           expected_semantic_site_count, logical_rows, payload_bytes, publication_state
         ) VALUES(64, 'go', 'go', 'seal-test', zeroblob(32), 0, 1, 0, 'building');",
    )
    .unwrap();
    assert_eq!(
        conn.execute(
            "UPDATE resolution_fragment_interiors SET publication_state = 'complete'
             WHERE blob_id = 64",
            [],
        )
        .unwrap(),
        1,
    );
    for blob_id in [1, 63, 64, 65, 128] {
        let sql: bool = conn
            .query_row("SELECT bifrost_seal_validates(?1)", [blob_id], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(sql, seal_validates(blob_id));
    }
}

#[test]
fn production_seal_validation_override() {
    const CHILD: &str = "BIFROST_SEAL_VALIDATION_OVERRIDE_CHILD";
    if let Some(mode) = std::env::var_os(CHILD) {
        let all = mode == "all" || cfg!(feature = "test-support");
        for blob_id in 1..=128 {
            assert_eq!(seal_validates(blob_id), all || blob_id % 64 == 0);
        }
        return;
    }
    for mode in ["sample", "all"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "production_seal_validation_override",
                "--nocapture",
            ])
            .env(CHILD, mode)
            .env("BIFROST_SEAL_VALIDATION", mode)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{mode}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }
}
