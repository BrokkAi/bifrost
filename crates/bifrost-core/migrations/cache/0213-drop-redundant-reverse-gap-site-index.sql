-- The WITHOUT ROWID primary key already covers every (blob_id, site) lookup.
DROP INDEX resolution_rust_reverse_gap_candidates_site;
