-- Distinguish same-named declarations by kind and signature (#7121).
--
-- Rows published before this migration recorded declaration reads under
-- the old key and cannot be verified under the new one. They are derived data
-- that the next run recomputes, so they are discarded rather than kept
-- unverifiable: policy units and evaluations, class-set summaries, and
-- procedure surfaces. Children go first because the migration does not rely
-- on foreign-key cascades being enabled.
DELETE FROM policy_evaluation_units;
DELETE FROM policy_evaluation_identities;
DELETE FROM policy_evaluation_policies;
DELETE FROM policy_evaluations;
DELETE FROM policy_unit_reads;
DELETE FROM policy_units;
DELETE FROM policy_read_keys;

DELETE FROM class_set_summary_charges;
DELETE FROM class_set_summary_dependency_sources;
DELETE FROM class_set_summary_dependencies;
DELETE FROM class_set_summary_exits;
DELETE FROM class_set_summary_reached;
DELETE FROM class_set_summary_reads;
DELETE FROM class_set_summary_facts;
DELETE FROM class_set_summaries;

DELETE FROM class_set_procedure_surface_bindings;
DELETE FROM class_set_procedure_surface_entered;
DELETE FROM class_set_procedure_surface_calls;
DELETE FROM class_set_procedure_surface_lexical_children;
DELETE FROM class_set_procedure_surface_reads;
DELETE FROM class_set_procedure_surfaces;

ALTER TABLE policy_read_keys ADD COLUMN decl_kind TEXT
  CHECK((decl_kind IS NOT NULL) = (kind = 'lookup' AND
        (family IS 'declaration_facts' OR family IS 'signature_metadata'
         OR family IS 'callers' OR family IS 'callees' OR family IS 'usages'
         OR family IS 'reference_candidates' OR family IS 'descendants')));

ALTER TABLE policy_read_keys ADD COLUMN decl_signature TEXT
  CHECK(decl_signature IS NULL OR decl_kind IS NOT NULL);

ALTER TABLE class_set_summary_reads ADD COLUMN decl_kind TEXT
  CHECK((decl_kind IS NOT NULL) = (kind = 'lookup' AND
        (family IS 'declaration_facts' OR family IS 'signature_metadata'
         OR family IS 'callers' OR family IS 'callees' OR family IS 'usages'
         OR family IS 'reference_candidates' OR family IS 'descendants')));

ALTER TABLE class_set_summary_reads ADD COLUMN decl_signature TEXT
  CHECK(decl_signature IS NULL OR decl_kind IS NOT NULL);

