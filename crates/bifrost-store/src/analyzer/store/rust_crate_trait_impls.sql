-- One derived row per implementation whose subject and trait both reached a
-- declaration: the blob and site that declare each end, the blob and site of
-- the impl that states it, and the file each of the three is placed in. A half
-- that reached none leaves no row here and a gap instead, so a row always
-- names two declarations.
--
-- The content address is the identity of each end. Each end also carries the
-- crate key, module path and name where its declaration is named (a half whose
-- chase reaches more than one placement has no declaration row), as the chase in
-- `rust_crate_trait_impl_declarations.sql` reached them, so a reader that
-- consumes another unit's summary reads the declaring unit's export by name.
INSERT INTO cr_trait_impls
SELECT * FROM (
SELECT subject.declaration_blob_id, subject.declaration_site, subject.rel_path,
       implemented.declaration_blob_id, implemented.declaration_site, implemented.rel_path,
       source.blob_id, source.impl_site, member.rel_path, source.impl_declaration_id,
       subject.declaring_unit_key, subject.declaring_module_path, subject.declaring_name,
       implemented.declaring_unit_key, implemented.declaring_module_path,
       implemented.declaring_name
FROM cr_impl_sources AS source
CROSS JOIN cr_members AS member ON member.module_path=source.module_path
  AND member.blob_id=source.blob_id
CROSS JOIN cr_impl_declarations AS subject ON subject.blob_id=source.blob_id
  AND subject.relation_key=source.relation_key AND subject.module_path=source.module_path
  AND subject.side='subject'
CROSS JOIN cr_impl_declarations AS implemented ON implemented.blob_id=source.blob_id
  AND implemented.relation_key=source.relation_key
  AND implemented.module_path=source.module_path AND implemented.side='trait'
) WHERE true ON CONFLICT DO NOTHING;
