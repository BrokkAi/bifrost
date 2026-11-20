-- #13416, COMPATIBLE-ADDITIVE. Older readers ignore this table; older writers
-- fire these persistent triggers, including writers in other processes sharing
-- the cache. Construction in one publisher cannot cover those writers. This is
-- the #9948 exception to the no-triggers rule (8213afec82), for these six inputs:
-- resolution_unit_summary_versions, resolution_unit_summaries,
-- resolution_unit_summary_dependencies, resolution_producer_epochs,
-- rust_resolution_unit_summary_versions, rust_resolution_unit_summary_contexts.
-- Other workspace projections are live views, not materialized selection rows.
-- BEFORE INSERT also observes rows displaced by OR REPLACE, even when an older
-- connection has recursive_triggers=OFF and implicit DELETE triggers do not run.
-- Every BEFORE INSERT and UPDATE covers the new row and all existing rows
-- conflicting on ANY primary or unique key. Old-row coverage must not depend
-- on the new row's qualification: REPLACE may remove a selected input while
-- inserting a row that contributes nothing to that selection. UPDATE excludes
-- OLD itself from the displaced set, and its WHEN includes every unique-key
-- column so that key-only changes cannot bypass displacement coverage.
-- Counters witness mutations, including committed net-zero rewrites.
CREATE TABLE workspace_selection_epochs (
 workspace_id TEXT NOT NULL,
 lang TEXT NOT NULL,
 generation INTEGER NOT NULL,
 revision INTEGER NOT NULL,
 epoch INTEGER NOT NULL CHECK(epoch > 0),
 PRIMARY KEY(workspace_id, lang, generation, revision)
) WITHOUT ROWID, STRICT;
-- Retain counters across workspace deletion/recreation to prevent an ABA reuse:
-- the same snapshot key must never regain an earlier epoch. No cascading FK.
-- New revisions acquire a counter on their first relevant input mutation.
INSERT INTO workspace_selection_epochs
 SELECT workspace_id, lang, generation, revision, 1 FROM workspace_revisions;

-- Conflicts: the full version PK, and the partial UNIQUE open-version key.
CREATE TRIGGER workspace_selection_epochs_resolution_unit_summary_versions_insert
BEFORE INSERT ON resolution_unit_summary_versions
BEGIN
 INSERT INTO workspace_selection_epochs(workspace_id, lang, generation, revision, epoch)
 SELECT r.workspace_id, r.lang, r.generation, r.revision, 1 FROM workspace_revisions AS r
 WHERE NEW.lang='rust' AND r.workspace_id=NEW.workspace_id AND r.lang=NEW.lang AND r.generation=NEW.generation AND r.revision>=NEW.valid_from AND (NEW.valid_until IS NULL OR r.revision<NEW.valid_until)
 UNION
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1 FROM resolution_unit_summary_versions AS v
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE v.lang='rust' AND v.workspace_id=NEW.workspace_id AND v.lang=NEW.lang AND v.generation=NEW.generation AND v.unit_key=NEW.unit_key AND v.profile_digest=NEW.profile_digest
 AND (v.valid_from=NEW.valid_from OR (v.valid_until IS NULL AND NEW.valid_until IS NULL))
 ON CONFLICT(workspace_id, lang, generation, revision)
 DO UPDATE SET epoch=workspace_selection_epochs.epoch+1;
END;

CREATE TRIGGER workspace_selection_epochs_resolution_unit_summary_versions_delete
BEFORE DELETE ON resolution_unit_summary_versions
WHEN OLD.lang='rust'
BEGIN
 INSERT INTO workspace_selection_epochs(workspace_id, lang, generation, revision, epoch)
 SELECT r.workspace_id, r.lang, r.generation, r.revision, 1 FROM workspace_revisions AS r
 WHERE OLD.lang='rust' AND r.workspace_id=OLD.workspace_id AND r.lang=OLD.lang AND r.generation=OLD.generation AND r.revision>=OLD.valid_from AND (OLD.valid_until IS NULL OR r.revision<OLD.valid_until) AND (1)
 ON CONFLICT(workspace_id, lang, generation, revision)
 DO UPDATE SET epoch=workspace_selection_epochs.epoch+1;
END;

CREATE TRIGGER workspace_selection_epochs_resolution_unit_summary_versions_update
BEFORE UPDATE ON resolution_unit_summary_versions
WHEN NOT (OLD.workspace_id IS NEW.workspace_id AND OLD.lang IS NEW.lang AND OLD.generation IS NEW.generation AND OLD.unit_key IS NEW.unit_key AND OLD.profile_digest IS NEW.profile_digest AND OLD.valid_from IS NEW.valid_from AND OLD.valid_until IS NEW.valid_until AND OLD.summary_id IS NEW.summary_id)
BEGIN
 INSERT INTO workspace_selection_epochs(workspace_id, lang, generation, revision, epoch)
 SELECT r.workspace_id, r.lang, r.generation, r.revision, 1 FROM workspace_revisions AS r
 WHERE OLD.lang='rust' AND r.workspace_id=OLD.workspace_id AND r.lang=OLD.lang AND r.generation=OLD.generation AND r.revision>=OLD.valid_from AND (OLD.valid_until IS NULL OR r.revision<OLD.valid_until) AND (NOT (OLD.workspace_id IS NEW.workspace_id AND OLD.lang IS NEW.lang AND OLD.generation IS NEW.generation AND OLD.unit_key IS NEW.unit_key AND OLD.profile_digest IS NEW.profile_digest AND OLD.valid_from IS NEW.valid_from AND OLD.summary_id IS NEW.summary_id) OR NOT (r.workspace_id=NEW.workspace_id AND r.lang=NEW.lang AND r.generation=NEW.generation AND r.revision>=NEW.valid_from AND (NEW.valid_until IS NULL OR r.revision<NEW.valid_until)))
 UNION
 SELECT r.workspace_id, r.lang, r.generation, r.revision, 1 FROM workspace_revisions AS r
 WHERE NEW.lang='rust' AND r.workspace_id=NEW.workspace_id AND r.lang=NEW.lang AND r.generation=NEW.generation AND r.revision>=NEW.valid_from AND (NEW.valid_until IS NULL OR r.revision<NEW.valid_until) AND (NOT (OLD.workspace_id IS NEW.workspace_id AND OLD.lang IS NEW.lang AND OLD.generation IS NEW.generation AND OLD.unit_key IS NEW.unit_key AND OLD.profile_digest IS NEW.profile_digest AND OLD.valid_from IS NEW.valid_from AND OLD.summary_id IS NEW.summary_id) OR NOT (r.workspace_id=OLD.workspace_id AND r.lang=OLD.lang AND r.generation=OLD.generation AND r.revision>=OLD.valid_from AND (OLD.valid_until IS NULL OR r.revision<OLD.valid_until)))
 UNION
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1 FROM resolution_unit_summary_versions AS v
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE v.lang='rust' AND v.workspace_id=NEW.workspace_id AND v.lang=NEW.lang AND v.generation=NEW.generation AND v.unit_key=NEW.unit_key AND v.profile_digest=NEW.profile_digest
 AND (v.valid_from=NEW.valid_from OR (v.valid_until IS NULL AND NEW.valid_until IS NULL))
 AND NOT (v.workspace_id IS OLD.workspace_id AND v.lang IS OLD.lang AND v.generation IS OLD.generation AND v.unit_key IS OLD.unit_key AND v.profile_digest IS OLD.profile_digest AND v.valid_from IS OLD.valid_from)
 ON CONFLICT(workspace_id, lang, generation, revision)
 DO UPDATE SET epoch=workspace_selection_epochs.epoch+1;
END;

-- Conflicts: summary_id INTEGER PRIMARY KEY, and UNIQUE(summary_digest).
CREATE TRIGGER workspace_selection_epochs_resolution_unit_summaries_insert
BEFORE INSERT ON resolution_unit_summaries
BEGIN
 INSERT INTO workspace_selection_epochs(workspace_id, lang, generation, revision, epoch)
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE NEW.lang='rust' AND v.lang='rust' AND v.summary_id=NEW.summary_id
 UNION
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summaries AS displaced
 JOIN resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary ON v.summary_id=displaced.summary_id
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE displaced.lang='rust' AND v.lang='rust'
 AND (displaced.summary_id=NEW.summary_id OR displaced.summary_digest=NEW.summary_digest)
 ON CONFLICT(workspace_id, lang, generation, revision)
 DO UPDATE SET epoch=workspace_selection_epochs.epoch+1;
END;

CREATE TRIGGER workspace_selection_epochs_resolution_unit_summaries_delete
BEFORE DELETE ON resolution_unit_summaries
WHEN OLD.lang='rust'
BEGIN
 INSERT INTO workspace_selection_epochs(workspace_id, lang, generation, revision, epoch)
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE v.lang='rust' AND v.summary_id=OLD.summary_id AND (1)
 ON CONFLICT(workspace_id, lang, generation, revision)
 DO UPDATE SET epoch=workspace_selection_epochs.epoch+1;
END;

CREATE TRIGGER workspace_selection_epochs_resolution_unit_summaries_update
BEFORE UPDATE ON resolution_unit_summaries
WHEN NOT (OLD.summary_id IS NEW.summary_id AND OLD.summary_digest IS NEW.summary_digest AND OLD.lang IS NEW.lang AND OLD.unit_kind IS NEW.unit_kind AND OLD.producer_epoch IS NEW.producer_epoch AND OLD.derivation_identity IS NEW.derivation_identity AND OLD.publication_state IS NEW.publication_state)
BEGIN
 INSERT INTO workspace_selection_epochs(workspace_id, lang, generation, revision, epoch)
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE v.lang='rust' AND v.summary_id=OLD.summary_id AND (1)
 UNION
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE v.lang='rust' AND v.summary_id=NEW.summary_id AND (1)
 UNION
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summaries AS displaced
 JOIN resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary ON v.summary_id=displaced.summary_id
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE displaced.lang='rust' AND v.lang='rust'
 AND (displaced.summary_id=NEW.summary_id OR displaced.summary_digest=NEW.summary_digest)
 AND NOT (displaced.summary_id IS OLD.summary_id)
 ON CONFLICT(workspace_id, lang, generation, revision)
 DO UPDATE SET epoch=workspace_selection_epochs.epoch+1;
END;

-- The INTEGER PRIMARY KEY(summary_id) is the only uniqueness constraint.
CREATE TRIGGER workspace_selection_epochs_rust_resolution_unit_summary_contexts_insert
BEFORE INSERT ON rust_resolution_unit_summary_contexts
BEGIN
 INSERT INTO workspace_selection_epochs(workspace_id, lang, generation, revision, epoch)
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE v.lang='rust' AND v.summary_id=NEW.summary_id
 UNION
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM rust_resolution_unit_summary_contexts AS displaced
 JOIN resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary ON v.summary_id=displaced.summary_id
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE v.lang='rust' AND displaced.summary_id=NEW.summary_id
 ON CONFLICT(workspace_id, lang, generation, revision)
 DO UPDATE SET epoch=workspace_selection_epochs.epoch+1;
END;

CREATE TRIGGER workspace_selection_epochs_rust_resolution_unit_summary_contexts_delete
BEFORE DELETE ON rust_resolution_unit_summary_contexts
BEGIN
 INSERT INTO workspace_selection_epochs(workspace_id, lang, generation, revision, epoch)
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE v.lang='rust' AND v.summary_id=OLD.summary_id AND (1)
 ON CONFLICT(workspace_id, lang, generation, revision)
 DO UPDATE SET epoch=workspace_selection_epochs.epoch+1;
END;

CREATE TRIGGER workspace_selection_epochs_rust_resolution_unit_summary_contexts_update
BEFORE UPDATE ON rust_resolution_unit_summary_contexts
WHEN NOT (OLD.summary_id IS NEW.summary_id)
BEGIN
 INSERT INTO workspace_selection_epochs(workspace_id, lang, generation, revision, epoch)
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE v.lang='rust' AND v.summary_id=OLD.summary_id AND (1)
 UNION
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE v.lang='rust' AND v.summary_id=NEW.summary_id AND (1)
 UNION
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM rust_resolution_unit_summary_contexts AS displaced
 JOIN resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary ON v.summary_id=displaced.summary_id
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE v.lang='rust' AND displaced.summary_id=NEW.summary_id
 AND NOT (displaced.summary_id IS OLD.summary_id)
 ON CONFLICT(workspace_id, lang, generation, revision)
 DO UPDATE SET epoch=workspace_selection_epochs.epoch+1;
END;

-- Conflicts: PK(summary_id, dependency_ordinal), UNIQUE(summary_id, dependency_unit_key).
CREATE TRIGGER workspace_selection_epochs_resolution_unit_summary_dependencies_insert
BEFORE INSERT ON resolution_unit_summary_dependencies
BEGIN
 INSERT INTO workspace_selection_epochs(workspace_id, lang, generation, revision, epoch)
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE NEW.boundary='workspace' AND v.lang='rust' AND v.summary_id=NEW.summary_id
 UNION
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summary_dependencies AS displaced
 JOIN resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary ON v.summary_id=displaced.summary_id
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE displaced.boundary='workspace' AND v.lang='rust' AND displaced.summary_id=NEW.summary_id
 AND (displaced.dependency_ordinal=NEW.dependency_ordinal OR displaced.dependency_unit_key=NEW.dependency_unit_key)
 ON CONFLICT(workspace_id, lang, generation, revision)
 DO UPDATE SET epoch=workspace_selection_epochs.epoch+1;
END;

CREATE TRIGGER workspace_selection_epochs_resolution_unit_summary_dependencies_delete
BEFORE DELETE ON resolution_unit_summary_dependencies
WHEN OLD.boundary='workspace'
BEGIN
 INSERT INTO workspace_selection_epochs(workspace_id, lang, generation, revision, epoch)
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE v.lang='rust' AND v.summary_id=OLD.summary_id AND (1)
 ON CONFLICT(workspace_id, lang, generation, revision)
 DO UPDATE SET epoch=workspace_selection_epochs.epoch+1;
END;

CREATE TRIGGER workspace_selection_epochs_resolution_unit_summary_dependencies_update
BEFORE UPDATE ON resolution_unit_summary_dependencies
WHEN NOT (OLD.summary_id IS NEW.summary_id AND OLD.dependency_ordinal IS NEW.dependency_ordinal AND OLD.dependency_unit_key IS NEW.dependency_unit_key AND OLD.boundary IS NEW.boundary)
BEGIN
 INSERT INTO workspace_selection_epochs(workspace_id, lang, generation, revision, epoch)
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE v.lang='rust' AND v.summary_id=OLD.summary_id AND (OLD.boundary='workspace')
 UNION
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE v.lang='rust' AND v.summary_id=NEW.summary_id AND (NEW.boundary='workspace')
 UNION
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summary_dependencies AS displaced
 JOIN resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary ON v.summary_id=displaced.summary_id
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE displaced.boundary='workspace' AND v.lang='rust' AND displaced.summary_id=NEW.summary_id
 AND (displaced.dependency_ordinal=NEW.dependency_ordinal OR displaced.dependency_unit_key=NEW.dependency_unit_key)
 AND NOT (displaced.summary_id IS OLD.summary_id AND displaced.dependency_ordinal IS OLD.dependency_ordinal)
 ON CONFLICT(workspace_id, lang, generation, revision)
 DO UPDATE SET epoch=workspace_selection_epochs.epoch+1;
END;

-- The only unique key is PK(workspace_id, lang, generation, unit_key, valid_from).
CREATE TRIGGER workspace_selection_epochs_rust_resolution_unit_summary_versions_insert
BEFORE INSERT ON rust_resolution_unit_summary_versions
BEGIN
 INSERT INTO workspace_selection_epochs(workspace_id, lang, generation, revision, epoch)
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE v.lang='rust' AND v.summary_id=NEW.summary_id AND v.workspace_id=NEW.workspace_id AND v.lang=NEW.lang AND v.generation=NEW.generation AND v.unit_key=NEW.unit_key AND v.valid_from=NEW.valid_from
 UNION
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM rust_resolution_unit_summary_versions AS displaced
 JOIN resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary ON v.summary_id=displaced.summary_id AND v.workspace_id=displaced.workspace_id AND v.lang=displaced.lang AND v.generation=displaced.generation AND v.unit_key=displaced.unit_key AND v.valid_from=displaced.valid_from
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE v.lang='rust' AND displaced.workspace_id=NEW.workspace_id AND displaced.lang=NEW.lang AND displaced.generation=NEW.generation AND displaced.unit_key=NEW.unit_key AND displaced.valid_from=NEW.valid_from
 ON CONFLICT(workspace_id, lang, generation, revision)
 DO UPDATE SET epoch=workspace_selection_epochs.epoch+1;
END;

CREATE TRIGGER workspace_selection_epochs_rust_resolution_unit_summary_versions_delete
BEFORE DELETE ON rust_resolution_unit_summary_versions
BEGIN
 INSERT INTO workspace_selection_epochs(workspace_id, lang, generation, revision, epoch)
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE v.lang='rust' AND v.summary_id=OLD.summary_id AND (v.workspace_id=OLD.workspace_id AND v.lang=OLD.lang AND v.generation=OLD.generation AND v.unit_key=OLD.unit_key AND v.valid_from=OLD.valid_from)
 ON CONFLICT(workspace_id, lang, generation, revision)
 DO UPDATE SET epoch=workspace_selection_epochs.epoch+1;
END;

CREATE TRIGGER workspace_selection_epochs_rust_resolution_unit_summary_versions_update
BEFORE UPDATE ON rust_resolution_unit_summary_versions
WHEN NOT (OLD.workspace_id IS NEW.workspace_id AND OLD.lang IS NEW.lang AND OLD.generation IS NEW.generation AND OLD.unit_key IS NEW.unit_key AND OLD.valid_from IS NEW.valid_from AND OLD.summary_id IS NEW.summary_id AND OLD.manifest_file_version_id IS NEW.manifest_file_version_id AND OLD.topology_id IS NEW.topology_id)
BEGIN
 INSERT INTO workspace_selection_epochs(workspace_id, lang, generation, revision, epoch)
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE v.lang='rust' AND v.summary_id=OLD.summary_id AND (v.workspace_id=OLD.workspace_id AND v.lang=OLD.lang AND v.generation=OLD.generation AND v.unit_key=OLD.unit_key AND v.valid_from=OLD.valid_from)
 UNION
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE v.lang='rust' AND v.summary_id=NEW.summary_id AND (v.workspace_id=NEW.workspace_id AND v.lang=NEW.lang AND v.generation=NEW.generation AND v.unit_key=NEW.unit_key AND v.valid_from=NEW.valid_from)
 UNION
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM rust_resolution_unit_summary_versions AS displaced
 JOIN resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary ON v.summary_id=displaced.summary_id AND v.workspace_id=displaced.workspace_id AND v.lang=displaced.lang AND v.generation=displaced.generation AND v.unit_key=displaced.unit_key AND v.valid_from=displaced.valid_from
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE v.lang='rust' AND displaced.workspace_id=NEW.workspace_id AND displaced.lang=NEW.lang AND displaced.generation=NEW.generation AND displaced.unit_key=NEW.unit_key AND displaced.valid_from=NEW.valid_from
 AND NOT (displaced.workspace_id IS OLD.workspace_id AND displaced.lang IS OLD.lang AND displaced.generation IS OLD.generation AND displaced.unit_key IS OLD.unit_key AND displaced.valid_from IS OLD.valid_from)
 ON CONFLICT(workspace_id, lang, generation, revision)
 DO UPDATE SET epoch=workspace_selection_epochs.epoch+1;
END;

-- The only unique key is PRIMARY KEY(lang).
CREATE TRIGGER workspace_selection_epochs_resolution_producer_epochs_insert
BEFORE INSERT ON resolution_producer_epochs
BEGIN
 INSERT INTO workspace_selection_epochs(workspace_id, lang, generation, revision, epoch)
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summaries AS s
 JOIN resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary ON v.summary_id=s.summary_id
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE NEW.lang='rust' AND v.lang='rust' AND s.producer_epoch=NEW.producer_epoch
 UNION
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_producer_epochs AS displaced
 JOIN resolution_unit_summaries AS s ON s.producer_epoch=displaced.producer_epoch
 JOIN resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary ON v.summary_id=s.summary_id
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE displaced.lang='rust' AND v.lang='rust' AND displaced.lang=NEW.lang
 ON CONFLICT(workspace_id, lang, generation, revision)
 DO UPDATE SET epoch=workspace_selection_epochs.epoch+1;
END;

CREATE TRIGGER workspace_selection_epochs_resolution_producer_epochs_delete
BEFORE DELETE ON resolution_producer_epochs
WHEN OLD.lang='rust'
BEGIN
 INSERT INTO workspace_selection_epochs(workspace_id, lang, generation, revision, epoch)
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summaries AS s
 JOIN resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary ON v.summary_id=s.summary_id
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE OLD.lang='rust' AND v.lang='rust' AND s.producer_epoch=OLD.producer_epoch
 ON CONFLICT(workspace_id, lang, generation, revision)
 DO UPDATE SET epoch=workspace_selection_epochs.epoch+1;
END;

CREATE TRIGGER workspace_selection_epochs_resolution_producer_epochs_update
BEFORE UPDATE ON resolution_producer_epochs
WHEN NOT (OLD.lang IS NEW.lang AND OLD.producer_epoch IS NEW.producer_epoch)
BEGIN
 INSERT INTO workspace_selection_epochs(workspace_id, lang, generation, revision, epoch)
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summaries AS s
 JOIN resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary ON v.summary_id=s.summary_id
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE OLD.lang='rust' AND v.lang='rust' AND s.producer_epoch=OLD.producer_epoch
 UNION
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_unit_summaries AS s
 JOIN resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary ON v.summary_id=s.summary_id
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE NEW.lang='rust' AND v.lang='rust' AND s.producer_epoch=NEW.producer_epoch
 UNION
 SELECT DISTINCT r.workspace_id, r.lang, r.generation, r.revision, 1
 FROM resolution_producer_epochs AS displaced
 JOIN resolution_unit_summaries AS s ON s.producer_epoch=displaced.producer_epoch
 JOIN resolution_unit_summary_versions AS v INDEXED BY resolution_unit_summary_versions_summary ON v.summary_id=s.summary_id
 JOIN workspace_revisions AS r ON r.workspace_id=v.workspace_id AND r.lang=v.lang AND r.generation=v.generation AND r.revision>=v.valid_from AND (v.valid_until IS NULL OR r.revision<v.valid_until)
 WHERE displaced.lang='rust' AND v.lang='rust' AND displaced.lang=NEW.lang
 AND NOT (displaced.lang IS OLD.lang)
 ON CONFLICT(workspace_id, lang, generation, revision)
 DO UPDATE SET epoch=workspace_selection_epochs.epoch+1;
END;
