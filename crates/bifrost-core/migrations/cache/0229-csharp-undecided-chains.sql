CREATE TABLE csharp_undecided_chains (
 blob_id INTEGER NOT NULL REFERENCES blobs(id) ON DELETE CASCADE,
 chain INTEGER NOT NULL,
 directive_start INTEGER NOT NULL,
 directive_end INTEGER NOT NULL,
 omitted_nonblank INTEGER NOT NULL CHECK(omitted_nonblank IN (0,1)),
 invalid_condition INTEGER NOT NULL CHECK(invalid_condition IN (0,1)),
 unknown_symbols BLOB NOT NULL CHECK(json_valid(unknown_symbols,8)),
 open_reasons BLOB NOT NULL CHECK(json_valid(open_reasons,8)),
 disagreeing_owners BLOB NOT NULL CHECK(json_valid(disagreeing_owners,8)),
 PRIMARY KEY(blob_id,chain)
) WITHOUT ROWID, STRICT;
CREATE INDEX idx_csharp_undecided_chains_nonblank ON csharp_undecided_chains(blob_id) WHERE omitted_nonblank = 1;
