-- One physical impl can occur in several module placements. Coalesce
-- identical placed identities, as the trait implementation producer does.
SELECT DISTINCT source.subject_name, source.blob_id, source.impl_site, member.rel_path,
       source.impl_declaration_id,
       CASE WHEN source.impl_declaration_id IS NULL THEN 'impl_item_unbridged'
            WHEN binding.relation_key IS NOT NULL THEN 'bound_without_declaration'
            ELSE 'unbound' END,
       binding.target_module_path
FROM cr_impl_sources AS source
CROSS JOIN cr_members AS member ON member.module_path=source.module_path
  AND member.blob_id=source.blob_id
LEFT JOIN cr_impl_bindings AS binding ON binding.blob_id=source.blob_id
  AND binding.relation_key=source.relation_key AND binding.module_path=source.module_path
  AND binding.side='subject'
WHERE source.trait_name IS NULL
  AND (source.impl_declaration_id IS NULL OR NOT EXISTS(
    SELECT 1 FROM cr_impl_declarations AS subject
    WHERE subject.blob_id=source.blob_id AND subject.relation_key=source.relation_key
      AND subject.module_path=source.module_path AND subject.side='subject'));
