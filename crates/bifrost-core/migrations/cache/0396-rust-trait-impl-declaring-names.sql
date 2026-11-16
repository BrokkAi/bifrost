-- #11173 walk slice 3b: a trait-impl row names the item that declares each end.
--
-- Compatible: the new columns are nullable and the tables hold derived cache rows.
-- RUST_CRATE_DERIVATION_VERSION moves with this migration, so no existing topology
-- is reused and every one is derived again with the columns filled; a build of an
-- older version keeps its own version-suffixed store file.
--
-- A row used to identify an end only by the content address of its declaration
-- (blob, site, rel_path). A unit summary then found the declaring unit by joining
-- that address to other topologies' exports, a join that the summary rows cannot
-- express by name, so the declaring unit was never recorded as a read. The row now
-- also carries where the declaration is named: the declaring crate key, the module
-- path and the name, as the derivation's own chase reaches them. All three are NULL
-- when the chase does not reach exactly one named declaration; the summary then
-- writes an unresolved endpoint.
ALTER TABLE rust_crate_trait_impls ADD COLUMN subject_declaring_crate_key BLOB
  CHECK(subject_declaring_crate_key IS NULL
        OR (typeof(subject_declaring_crate_key) = 'blob' AND length(subject_declaring_crate_key) = 32));
ALTER TABLE rust_crate_trait_impls ADD COLUMN subject_declaring_module_path TEXT;
ALTER TABLE rust_crate_trait_impls ADD COLUMN subject_declaring_name TEXT
  CHECK((subject_declaring_crate_key IS NULL) = (subject_declaring_name IS NULL)
        AND (subject_declaring_crate_key IS NULL) = (subject_declaring_module_path IS NULL)
        AND (subject_declaring_name IS NULL OR length(subject_declaring_name) > 0));
ALTER TABLE rust_crate_trait_impls ADD COLUMN trait_declaring_crate_key BLOB
  CHECK(trait_declaring_crate_key IS NULL
        OR (typeof(trait_declaring_crate_key) = 'blob' AND length(trait_declaring_crate_key) = 32));
ALTER TABLE rust_crate_trait_impls ADD COLUMN trait_declaring_module_path TEXT;
ALTER TABLE rust_crate_trait_impls ADD COLUMN trait_declaring_name TEXT
  CHECK((trait_declaring_crate_key IS NULL) = (trait_declaring_name IS NULL)
        AND (trait_declaring_crate_key IS NULL) = (trait_declaring_module_path IS NULL)
        AND (trait_declaring_name IS NULL OR length(trait_declaring_name) > 0));

-- The half that did reach a declaration, for the unit-summary writer's subject
-- endpoint of an impl whose trait did not.
ALTER TABLE rust_crate_unresolved_trait_impls ADD COLUMN declaring_crate_key BLOB
  CHECK(declaring_crate_key IS NULL
        OR (typeof(declaring_crate_key) = 'blob' AND length(declaring_crate_key) = 32));
ALTER TABLE rust_crate_unresolved_trait_impls ADD COLUMN declaring_module_path TEXT;
ALTER TABLE rust_crate_unresolved_trait_impls ADD COLUMN declaring_name TEXT
  CHECK((declaring_crate_key IS NULL) = (declaring_name IS NULL)
        AND (declaring_crate_key IS NULL) = (declaring_module_path IS NULL)
        AND (declaring_name IS NULL OR length(declaring_name) > 0));
