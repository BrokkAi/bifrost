CREATE TEMP TABLE IF NOT EXISTS selected_rust_transient_placement_attributes (
 mount_ordinal INTEGER NOT NULL,
 summary_id INTEGER NOT NULL,
 container_path TEXT NOT NULL,
 member_ordinal INTEGER NOT NULL CHECK(member_ordinal >= 0),
 scope_ordinal INTEGER NOT NULL CHECK(scope_ordinal >= 0),
 module_declaration INTEGER,
 PRIMARY KEY(mount_ordinal, summary_id, container_path, member_ordinal, scope_ordinal)
) WITHOUT ROWID, STRICT;
-- PLACEMENTS and REFERENCE_PLACEMENTS seek a selected module declaration.
CREATE INDEX IF NOT EXISTS temp.selected_rust_transient_placement_attributes_declaration
 ON selected_rust_transient_placement_attributes(module_declaration, summary_id, container_path, member_ordinal, mount_ordinal, scope_ordinal);
CREATE TEMP VIEW IF NOT EXISTS selected_rust_container_placements AS
 SELECT p.mount_ordinal, mount.blob_id, p.scope_ordinal,
        a.module_declaration, owner.topology_id, owner.unit_key,
        p.summary_id, p.member_ordinal,
        CASE p.container_path WHEN '' THEN 'crate' ELSE p.container_path END AS container_path,
        member.blob_id AS placement_blob
 FROM selected_resolution_transient_placements AS p
 JOIN selected_rust_transient_placement_attributes AS a
   USING(mount_ordinal, summary_id, container_path, member_ordinal, scope_ordinal)
 JOIN selected_resolution_mounts AS mount ON mount.mount_ordinal=p.mount_ordinal
 JOIN selected_rust_unit_summaries AS owner ON owner.summary_id=p.summary_id
 JOIN main.resolution_unit_summary_members AS member
   ON member.summary_id=p.summary_id AND member.member_ordinal=p.member_ordinal;
