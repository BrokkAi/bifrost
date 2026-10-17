use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

#[allow(clippy::too_many_arguments)]
pub fn accepted_suppression_record(
    policy_id: &str,
    finding_id: &str,
    policy_hash: Option<&str>,
    reason: &str,
    accepted_by: Option<&str>,
    expires_at: Option<&str>,
    path: Option<&str>,
) -> Value {
    let mut record = json!({
        "policy_id": policy_id,
        "finding_id": finding_id,
        "identity_stability": "strong",
        "status": "accepted",
        "reason": reason,
        "policy_hash_at_acceptance": policy_hash,
        "accepted_at": "2026-07-01",
        "expires_at": expires_at,
    });
    if let Some(accepted_by) = accepted_by {
        record
            .as_object_mut()
            .expect("record object")
            .insert("accepted_by".to_owned(), json!(accepted_by));
    }
    if let Some(path) = path {
        record
            .as_object_mut()
            .expect("record object")
            .insert("path".to_owned(), json!(path));
    }
    record
}

pub fn write_policy_suppressions(
    root: &Path,
    relative_path: impl AsRef<Path>,
    records: Vec<Value>,
) {
    let path: PathBuf = root.join(relative_path);
    fs::create_dir_all(path.parent().expect("suppression parent"))
        .expect("create suppression directory");
    fs::write(
        path,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "suppressions": records,
        }))
        .expect("suppression JSON"),
    )
    .expect("write suppressions");
}
