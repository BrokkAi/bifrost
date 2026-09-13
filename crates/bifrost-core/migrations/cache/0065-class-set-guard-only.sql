-- Class membership from a guard on an unmodeled producer does not admit a
-- value alternative. Keep that distinction in finding-free root replay.
ALTER TABLE class_set_finding_free_root_rows
ADD COLUMN guard_only INTEGER NOT NULL DEFAULT 0
  CHECK(guard_only IN (0, 1)
        AND (guard_only = 0 OR atom_kind IN ('workspace', 'external')));
