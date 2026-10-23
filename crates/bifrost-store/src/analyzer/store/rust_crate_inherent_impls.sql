-- One physical impl can occur in several module placements. Coalesce
-- identical placed identities, as the trait implementation producer does.
SELECT DISTINCT subject.declaration_blob_id, subject.declaration_site, subject.rel_path,
       source.blob_id, source.impl_site, member.rel_path, source.impl_declaration_id
FROM cr_impl_sources AS source
CROSS JOIN cr_members AS member ON member.module_path=source.module_path
  AND member.blob_id=source.blob_id
CROSS JOIN cr_impl_declarations AS subject ON subject.blob_id=source.blob_id
  AND subject.relation_key=source.relation_key AND subject.module_path=source.module_path
  AND subject.side='subject'
WHERE source.trait_name IS NULL AND source.impl_declaration_id IS NOT NULL;
