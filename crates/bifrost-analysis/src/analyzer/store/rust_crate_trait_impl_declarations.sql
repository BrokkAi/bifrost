-- The declaration each half of an impl header names, and the file that
-- declares it.
--
-- The triple a half binds is where its spelling resolved, and one type can be
-- bound under more than one of them: a module that re-exports `dep::inner::Name`
-- binds it under its own path while the declaring crate binds it under
-- `crate::inner`. A derived row keyed by the triple would therefore miss a
-- reference that names the same type another way, and a miss on this table is a
-- `no_definition` answer. The route walk already chases the module half to the
-- container that declares it; this finishes the name half the same way, so both
-- ends of a row are the declaration itself.
--
-- A declaration's `(blob, site)` is content-addressed, so it does not say which
-- file declares it: two byte-identical files are one blob. The placement is
-- the file of the module that declares the name, and when the bound name is a
-- re-export the declaring module is found by following the re-export the way
-- Rust does: a named `use` step when the module has one, otherwise the
-- module's glob steps, unless the module declares the name itself, which
-- shadows every glob. The chase ends at the export row that declares the name
-- with the same `(blob, site)` the binding read. Both relations it walks,
-- `cr_reexport_steps` and `cr_glob_steps`, already hold this crate's own
-- steps, private ones included, and the steps the derived crates published.
--
-- A half whose chase ends at more than one file names no single declaration.
-- Rust rejects such a name as ambiguous, so the half binds nothing here and
-- its impl is recorded as bound without a declaration.
INSERT OR IGNORE INTO cr_impl_declarations
WITH RECURSIVE chase(blob_id, relation_key, module_path, side, declaration_blob_id,
                     declaration_site, crate_key, at_module, at_name) AS (
  SELECT binding.blob_id, binding.relation_key, binding.module_path, binding.side,
         exports.declaration_blob_id, exports.declaration_site,
         binding.target_crate_key, binding.target_module_path, binding.target_name
  FROM cr_impl_bindings AS binding
  CROSS JOIN cr_exports AS exports ON exports.crate_key=binding.target_crate_key
    AND exports.module_path=binding.target_module_path
    AND exports.namespace='type' AND exports.name=binding.target_name
  UNION
  SELECT chase.blob_id, chase.relation_key, chase.module_path, chase.side,
         chase.declaration_blob_id, chase.declaration_site,
         step.target_crate_key, step.target_module_path, step.target_name
  FROM chase
  CROSS JOIN cr_reexport_steps AS step ON step.crate_key=chase.crate_key
    AND step.module_path=chase.at_module AND step.bound_name=chase.at_name
  UNION
  SELECT chase.blob_id, chase.relation_key, chase.module_path, chase.side,
         chase.declaration_blob_id, chase.declaration_site,
         glob.target_crate_key, glob.target_module_path, chase.at_name
  FROM chase
  CROSS JOIN cr_glob_steps AS glob ON glob.crate_key=chase.crate_key
    AND glob.module_path=chase.at_module
  WHERE NOT EXISTS(SELECT 1 FROM cr_reexport_steps AS named
                   WHERE named.crate_key=chase.crate_key AND named.module_path=chase.at_module
                     AND named.bound_name=chase.at_name)
    AND NOT EXISTS(SELECT 1 FROM cr_exports AS declared
                   WHERE declared.crate_key=chase.crate_key
                     AND declared.module_path=chase.at_module
                     AND declared.namespace='type' AND declared.name=chase.at_name
                     AND declared.origin='declaration')
    AND NOT EXISTS(SELECT 1 FROM cr_foreign AS dependency
                   CROSS JOIN rust_crate_exports AS declared
                     ON declared.topology_id=dependency.topology_id
                    AND declared.module_path=chase.at_module
                    AND declared.namespace='type' AND declared.name=chase.at_name
                   WHERE dependency.crate_key=chase.crate_key
                     AND declared.origin='declaration')
),
placements(blob_id, relation_key, module_path, side, declaration_blob_id,
           declaration_site, rel_path) AS (
  SELECT chase.blob_id, chase.relation_key, chase.module_path, chase.side,
         chase.declaration_blob_id, chase.declaration_site, member.rel_path
  FROM chase
  CROSS JOIN cr_identity AS identity ON identity.crate_key=chase.crate_key
  CROSS JOIN cr_exports AS declared ON declared.crate_key=chase.crate_key
    AND declared.module_path=chase.at_module
    AND declared.namespace='type' AND declared.name=chase.at_name
  CROSS JOIN cr_members AS member ON member.module_path=chase.at_module
    AND member.blob_id=chase.declaration_blob_id
  WHERE declared.origin='declaration'
    AND declared.declaration_blob_id=chase.declaration_blob_id
    AND declared.declaration_site=chase.declaration_site
  UNION
  SELECT chase.blob_id, chase.relation_key, chase.module_path, chase.side,
         chase.declaration_blob_id, chase.declaration_site, source.rel_path
  FROM chase
  CROSS JOIN cr_foreign AS dependency ON dependency.crate_key=chase.crate_key
  CROSS JOIN rust_crate_exports AS declared ON declared.topology_id=dependency.topology_id
    AND declared.module_path=chase.at_module
    AND declared.namespace='type' AND declared.name=chase.at_name
  CROSS JOIN rust_crate_container_sources AS source
    ON source.topology_id=dependency.topology_id
   AND source.container_path=chase.at_module
   AND source.blob_id=chase.declaration_blob_id
  WHERE declared.origin='declaration'
    AND declared.declaration_blob_id=chase.declaration_blob_id
    AND declared.declaration_site=chase.declaration_site
)
SELECT blob_id, relation_key, module_path, side, declaration_blob_id, declaration_site,
       min(rel_path)
FROM placements
GROUP BY blob_id, relation_key, module_path, side
HAVING count(DISTINCT rel_path) = 1;
