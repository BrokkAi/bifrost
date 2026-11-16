-- One physical impl can occur in several module placements. Coalesce
-- identical placed identities, as the trait implementation producer does.
--
-- The subject also carries the name form of the declaration it resolved to (the
-- declaring unit, module path, kind, namespace and name), copied from the
-- chase that found it. Each placement's half names one placement of the
-- declaration (the chase refuses more), but two placements of one physical impl
-- can reach one physical declaration that is itself placed twice, so the name
-- form is not part of the identity above. An own subject is written as the
-- member and site, which every such placement shares, so which own name form is
-- kept does not change the summary row. A name form in this crate is preferred:
-- an inherent impl can only implement a type of its own crate, so a placement
-- that reached another crate's copy of a shared file is the rejected one. Among
-- the rest the lowest by every column is kept, independent of row order.
SELECT subject_declaration_blob_id, subject_declaration_site, subject_rel_path,
       impl_blob_id, impl_site, impl_rel_path, impl_declaration_id,
       declaring_unit_key, declaring_module_path, 'declaration', 'type', declaring_name,
       'declaration'
FROM (
  SELECT subject.declaration_blob_id AS subject_declaration_blob_id,
         subject.declaration_site AS subject_declaration_site,
         subject.rel_path AS subject_rel_path,
         source.blob_id AS impl_blob_id, source.impl_site AS impl_site,
         member.rel_path AS impl_rel_path, source.impl_declaration_id AS impl_declaration_id,
         subject.declaring_unit_key AS declaring_unit_key,
         subject.declaring_module_path AS declaring_module_path,
         subject.declaring_name AS declaring_name,
         row_number() OVER (
           PARTITION BY subject.declaration_blob_id, subject.declaration_site,
                        subject.rel_path, source.blob_id, source.impl_site, member.rel_path
           ORDER BY subject.declaring_unit_key <> (SELECT crate_key FROM cr_identity),
                    source.impl_declaration_id, subject.declaring_unit_key,
                    subject.declaring_module_path, subject.declaring_name) AS rank
  FROM cr_impl_sources AS source
  CROSS JOIN cr_members AS member ON member.module_path=source.module_path
    AND member.blob_id=source.blob_id
  CROSS JOIN cr_impl_declarations AS subject ON subject.blob_id=source.blob_id
    AND subject.relation_key=source.relation_key AND subject.module_path=source.module_path
    AND subject.side='subject'
  WHERE source.trait_name IS NULL AND source.impl_declaration_id IS NOT NULL
)
WHERE rank = 1;
