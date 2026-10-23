-- One derived row per implementation whose subject and trait both reached a
-- declaration: the blob and site that declare each end, the blob and site of
-- the impl that states it, and the file each of the three is placed in. A half
-- that reached none leaves no row here and a gap instead, so a row always
-- names two declarations.
--
-- The row carries no names. A reader that wants them joins
-- `rust_crate_exports` by `rust_crate_exports_declaration`, which is a
-- two-column seek covered by that index; duplicating the crate key, module path
-- and name here would give one type two spellings and let them drift.
INSERT OR IGNORE INTO cr_trait_impls
SELECT subject.declaration_blob_id, subject.declaration_site, subject.rel_path,
       implemented.declaration_blob_id, implemented.declaration_site, implemented.rel_path,
       source.blob_id, source.impl_site, member.rel_path, source.impl_declaration_id
FROM cr_impl_sources AS source
CROSS JOIN cr_members AS member ON member.module_path=source.module_path
  AND member.blob_id=source.blob_id
CROSS JOIN cr_impl_declarations AS subject ON subject.blob_id=source.blob_id
  AND subject.relation_key=source.relation_key AND subject.module_path=source.module_path
  AND subject.side='subject'
CROSS JOIN cr_impl_declarations AS implemented ON implemented.blob_id=source.blob_id
  AND implemented.relation_key=source.relation_key
  AND implemented.module_path=source.module_path AND implemented.side='trait';
