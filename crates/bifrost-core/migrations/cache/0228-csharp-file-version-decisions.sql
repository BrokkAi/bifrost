CREATE TABLE csharp_file_version_decisions (
    file_version_id INTEGER PRIMARY KEY REFERENCES workspace_file_versions(file_version_id) ON DELETE CASCADE,
    decision_digest BLOB NOT NULL CHECK(length(decision_digest)=32),
    assignment_digest BLOB NOT NULL CHECK(length(assignment_digest)=32)
) STRICT;

CREATE TABLE csharp_source_condition_symbols (
    blob_id INTEGER NOT NULL REFERENCES blobs(id) ON DELETE CASCADE,
    symbol TEXT NOT NULL,
    PRIMARY KEY(blob_id, symbol)
) WITHOUT ROWID, STRICT;
