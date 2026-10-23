-- Subject-only headers use the same module placement and binding algorithm
-- as trait headers. The source ID was bridged during blob lowering.
INSERT INTO cr_impl_sources
SELECT DISTINCT members.blob_id, subject.relation_key, members.module_path, subject.impl_site,
       subject.terminal_spelling, subject.position, NULL, NULL, subject.impl_declaration_id
FROM cr_members AS members
CROSS JOIN resolution_inherent_implementations AS subject
  ON subject.blob_id=members.blob_id AND subject.segment IS NULL
{placement};
