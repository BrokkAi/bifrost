-- Selection-local projections of proved predecessor container placements.
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_transient_placements (
 mount_ordinal INTEGER NOT NULL,
 summary_id INTEGER NOT NULL,
 container_path TEXT NOT NULL,
 member_ordinal INTEGER NOT NULL CHECK(member_ordinal >= 0),
 scope_ordinal INTEGER NOT NULL CHECK(scope_ordinal >= 0),
 PRIMARY KEY(mount_ordinal, summary_id, container_path, member_ordinal, scope_ordinal)
) WITHOUT ROWID, STRICT;
-- REFERENCE_MODULE_PLACEMENTS and PREFIX_MODULES seek a selected mount scope.
CREATE INDEX IF NOT EXISTS temp.selected_resolution_transient_placements_scope
 ON selected_resolution_transient_placements(mount_ordinal, scope_ordinal);
-- GAP_CANDIDATE_SITES_SQL enumerates all selected hosts of a summary.
CREATE INDEX IF NOT EXISTS temp.selected_resolution_transient_placements_summary
 ON selected_resolution_transient_placements(summary_id, container_path);
-- PLACEMENTS and REFERENCE_PLACEMENTS start from the predecessor member.
CREATE INDEX IF NOT EXISTS temp.selected_resolution_transient_placements_member
 ON selected_resolution_transient_placements(summary_id, member_ordinal, container_path);
