-- Name each lowered copy of a procedure-local call (#6638).
--
-- A procedure-dispatch read names its call by the byte interval relative to
-- the owning procedure. Lowering can give one source call several call rows
-- at that interval: a Python `finally` body is lowered once per exit path. The
-- interval alone named none of them, so every such read was unattributed and
-- marked its ledger unbounded. `site_ordinal` is the call's position among the
-- procedure's call rows at the interval, and it is part of the read key.
--
-- Rows published before this migration recorded procedure-dispatch reads under
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

-- A procedure-dispatch read carries the ordinal and no other read does.
ALTER TABLE policy_read_keys ADD COLUMN site_ordinal INTEGER
  CHECK((site_ordinal IS NOT NULL) = (kind = 'lookup' AND family IS 'procedure_dispatch')
        AND (site_ordinal IS NULL OR site_ordinal >= 0));

ALTER TABLE class_set_summary_reads ADD COLUMN site_ordinal INTEGER
  CHECK((site_ordinal IS NOT NULL) = (kind = 'lookup' AND family IS 'procedure_dispatch')
        AND (site_ordinal IS NULL OR site_ordinal >= 0));

-- Every surface read is a procedure-dispatch read, and the table is empty.
ALTER TABLE class_set_procedure_surface_reads ADD COLUMN site_ordinal INTEGER NOT NULL
  CHECK(site_ordinal >= 0);
