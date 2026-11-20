-- FINAL 0482 assigned by native-engine coordinator at the last pre-Ready merge.
-- #10979: a request compares these scalar witnesses inside each consuming
-- transaction. Epoch strings and revision numbers can return to earlier values;
-- committed sequence values cannot. Missing witness rows are stale, not zero.
-- Compatible for every shipped predecessor: existing publications start at zero
-- without changing selected facts. Older writers run the installed triggers;
-- the new reader accepts the backfilled zero proof until a real transition.
-- Unchanged revision UPDATEs remain legal; only identity changes are refused.
-- No old rows or persisted keys are invalidated and no minimum version rises.
CREATE TABLE selected_publication_sequences(
  kind TEXT NOT NULL CHECK(kind IN ('revision', 'resolution', 'semantic_ir')),
  lang TEXT NOT NULL CHECK(kind <> 'revision' OR lang = ''),
  value INTEGER NOT NULL CHECK(value >= 0),
  PRIMARY KEY(kind, lang)
) WITHOUT ROWID, STRICT;

INSERT INTO selected_publication_sequences VALUES('revision', '', 0);
INSERT INTO selected_publication_sequences
  SELECT 'resolution', lang, 0 FROM resolution_producer_epochs;
INSERT INTO selected_publication_sequences
  SELECT 'semantic_ir', lang, 0 FROM semantic_ir_producer_epochs;

-- Tombstones survive producer deletion. BEFORE INSERT rejects REPLACE even
-- when recursive_triggers is OFF (SQLite then omits implicit delete triggers).
CREATE TRIGGER selected_publication_sequences_no_replace
BEFORE INSERT ON selected_publication_sequences
WHEN EXISTS(SELECT 1 FROM selected_publication_sequences
            WHERE kind = NEW.kind AND lang = NEW.lang)
BEGIN
  SELECT RAISE(ABORT, 'selected publication sequence cannot be replaced');
END;
CREATE TRIGGER selected_publication_sequences_monotonic
BEFORE UPDATE ON selected_publication_sequences
WHEN OLD.kind IS NOT NEW.kind OR OLD.lang IS NOT NEW.lang OR NEW.value < OLD.value
BEGIN
  SELECT RAISE(ABORT, 'selected publication sequence cannot decrease or change key');
END;
CREATE TRIGGER selected_publication_sequences_no_delete
BEFORE DELETE ON selected_publication_sequences
BEGIN
  SELECT RAISE(ABORT, 'selected publication sequence tombstone cannot be deleted');
END;

CREATE TABLE workspace_revision_incarnations(
  workspace_id TEXT NOT NULL,
  lang TEXT NOT NULL,
  generation INTEGER NOT NULL,
  revision INTEGER NOT NULL,
  incarnation INTEGER NOT NULL CHECK(incarnation >= 0),
  PRIMARY KEY(workspace_id, lang, generation, revision),
  FOREIGN KEY(workspace_id, lang, generation, revision)
    REFERENCES workspace_revisions(workspace_id, lang, generation, revision)
    ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
INSERT INTO workspace_revision_incarnations
  SELECT workspace_id, lang, generation, revision, 0 FROM workspace_revisions;

CREATE TRIGGER workspace_revision_incarnations_no_replace
BEFORE INSERT ON workspace_revision_incarnations
WHEN EXISTS(SELECT 1 FROM workspace_revision_incarnations
            WHERE workspace_id = NEW.workspace_id AND lang = NEW.lang
              AND generation = NEW.generation AND revision = NEW.revision)
BEGIN
  SELECT RAISE(ABORT, 'workspace revision incarnation cannot be replaced');
END;
CREATE TRIGGER workspace_revision_incarnations_immutable
BEFORE UPDATE ON workspace_revision_incarnations
BEGIN
  SELECT RAISE(ABORT, 'workspace revision incarnation is immutable');
END;
CREATE TRIGGER workspace_revision_incarnations_no_direct_delete
BEFORE DELETE ON workspace_revision_incarnations
WHEN EXISTS(SELECT 1 FROM workspace_revisions
            WHERE workspace_id = OLD.workspace_id AND lang = OLD.lang
              AND generation = OLD.generation AND revision = OLD.revision)
BEGIN
  SELECT RAISE(ABORT, 'workspace revision witness requires its revision');
END;
CREATE TRIGGER workspace_revisions_immutable
BEFORE UPDATE ON workspace_revisions
WHEN OLD.workspace_id IS NOT NEW.workspace_id OR OLD.lang IS NOT NEW.lang
  OR OLD.generation IS NOT NEW.generation OR OLD.revision IS NOT NEW.revision
BEGIN
  SELECT RAISE(ABORT, 'workspace revision identity is immutable');
END;
CREATE TRIGGER workspace_revisions_allocate_incarnation
AFTER INSERT ON workspace_revisions
BEGIN
  UPDATE selected_publication_sequences SET value = value + 1
    WHERE kind = 'revision' AND lang = '';
  INSERT INTO selected_publication_sequences
    SELECT 'revision', '', 1 WHERE NOT EXISTS(
      SELECT 1 FROM selected_publication_sequences WHERE kind = 'revision' AND lang = '');
  INSERT INTO workspace_revision_incarnations
    SELECT NEW.workspace_id, NEW.lang, NEW.generation, NEW.revision, value
    FROM selected_publication_sequences WHERE kind = 'revision' AND lang = '';
END;

-- All allocations use the same named sequence relation and UPDATE followed by
-- conditional INSERT. Unlike a counter UPSERT, this also works under an outer
-- INSERT OR REPLACE, whose conflict policy applies to statements in triggers.
CREATE TRIGGER resolution_producer_epochs_advance_insert
AFTER INSERT ON resolution_producer_epochs
BEGIN
  UPDATE selected_publication_sequences SET value = value + 1
    WHERE kind = 'resolution' AND lang = NEW.lang;
  INSERT INTO selected_publication_sequences
    SELECT 'resolution', NEW.lang, 1 WHERE NOT EXISTS(
      SELECT 1 FROM selected_publication_sequences WHERE kind = 'resolution' AND lang = NEW.lang);
END;
CREATE TRIGGER resolution_producer_epochs_advance_update
AFTER UPDATE ON resolution_producer_epochs
WHEN OLD.producer_epoch IS NOT NEW.producer_epoch OR OLD.lang IS NOT NEW.lang
BEGIN
  UPDATE selected_publication_sequences SET value = value + 1
    WHERE kind = 'resolution' AND (lang = NEW.lang OR lang = OLD.lang);
  INSERT INTO selected_publication_sequences
    SELECT 'resolution', NEW.lang, 1 WHERE NOT EXISTS(
      SELECT 1 FROM selected_publication_sequences WHERE kind = 'resolution' AND lang = NEW.lang);
END;
CREATE TRIGGER resolution_producer_epochs_advance_delete
AFTER DELETE ON resolution_producer_epochs
BEGIN
  UPDATE selected_publication_sequences SET value = value + 1
    WHERE kind = 'resolution' AND lang = OLD.lang;
  INSERT INTO selected_publication_sequences
    SELECT 'resolution', OLD.lang, 1 WHERE NOT EXISTS(
      SELECT 1 FROM selected_publication_sequences WHERE kind = 'resolution' AND lang = OLD.lang);
END;
CREATE TRIGGER semantic_ir_producer_epochs_advance_insert
AFTER INSERT ON semantic_ir_producer_epochs
BEGIN
  UPDATE selected_publication_sequences SET value = value + 1
    WHERE kind = 'semantic_ir' AND lang = NEW.lang;
  INSERT INTO selected_publication_sequences
    SELECT 'semantic_ir', NEW.lang, 1 WHERE NOT EXISTS(
      SELECT 1 FROM selected_publication_sequences WHERE kind = 'semantic_ir' AND lang = NEW.lang);
END;
CREATE TRIGGER semantic_ir_producer_epochs_advance_update
AFTER UPDATE ON semantic_ir_producer_epochs
WHEN OLD.producer_epoch IS NOT NEW.producer_epoch OR OLD.lang IS NOT NEW.lang
BEGIN
  UPDATE selected_publication_sequences SET value = value + 1
    WHERE kind = 'semantic_ir' AND (lang = NEW.lang OR lang = OLD.lang);
  INSERT INTO selected_publication_sequences
    SELECT 'semantic_ir', NEW.lang, 1 WHERE NOT EXISTS(
      SELECT 1 FROM selected_publication_sequences WHERE kind = 'semantic_ir' AND lang = NEW.lang);
END;
CREATE TRIGGER semantic_ir_producer_epochs_advance_delete
AFTER DELETE ON semantic_ir_producer_epochs
BEGIN
  UPDATE selected_publication_sequences SET value = value + 1
    WHERE kind = 'semantic_ir' AND lang = OLD.lang;
  INSERT INTO selected_publication_sequences
    SELECT 'semantic_ir', OLD.lang, 1 WHERE NOT EXISTS(
      SELECT 1 FROM selected_publication_sequences WHERE kind = 'semantic_ir' AND lang = OLD.lang);
END;
