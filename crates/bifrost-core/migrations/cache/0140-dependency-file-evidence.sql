-- Static file facts are selected by the same immutable input revision as code.
CREATE TABLE dependency_evidence_sets (
    set_id INTEGER PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    lang TEXT NOT NULL,
    generation INTEGER NOT NULL,
    input_digest TEXT NOT NULL,
    UNIQUE(workspace_id, lang, generation, input_digest)
);
CREATE TABLE dependency_evidence_selections (
    workspace_id TEXT NOT NULL,
    lang TEXT NOT NULL,
    generation INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    set_id INTEGER NOT NULL REFERENCES dependency_evidence_sets(set_id) ON DELETE CASCADE,
    PRIMARY KEY(workspace_id, lang, generation, revision),
    FOREIGN KEY(workspace_id, lang, generation, revision)
        REFERENCES workspace_revisions(workspace_id, lang, generation, revision) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE TABLE dependency_file_evidence (
    set_id INTEGER NOT NULL REFERENCES dependency_evidence_sets(set_id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    package TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('declared','constraint','locked','installed','checksum')),
    version_requirement TEXT,
    exact_version TEXT,
    source TEXT,
    locator TEXT,
    declared_by TEXT,
    scope TEXT NOT NULL,
    conditions TEXT NOT NULL CHECK(json_valid(conditions)),
    build_file TEXT NOT NULL,
    source_digest TEXT NOT NULL,
    start_byte INTEGER NOT NULL,
    end_byte INTEGER NOT NULL,
    complete INTEGER NOT NULL CHECK(complete IN (0,1)),
    PRIMARY KEY(set_id,id)
) WITHOUT ROWID;
CREATE INDEX idx_dependency_file_evidence_package ON dependency_file_evidence(set_id,ecosystem,package,exact_version,source);
CREATE TABLE dependency_file_gaps (
    set_id INTEGER NOT NULL REFERENCES dependency_evidence_sets(set_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    kind TEXT NOT NULL,
    build_file TEXT NOT NULL,
    start_byte INTEGER NOT NULL,
    end_byte INTEGER NOT NULL,
    message TEXT NOT NULL,
    PRIMARY KEY(set_id,ordinal)
) WITHOUT ROWID;

-- A revision/image lease deletion also reclaims its unreferenced facts.
CREATE TRIGGER dependency_selection_gc AFTER DELETE ON dependency_evidence_selections
BEGIN
    DELETE FROM dependency_evidence_sets WHERE set_id=OLD.set_id
        AND NOT EXISTS(SELECT 1 FROM dependency_evidence_selections WHERE set_id=OLD.set_id);
END;
CREATE INDEX idx_dependency_evidence_selections_set ON dependency_evidence_selections(set_id);

CREATE TRIGGER dependency_selection_replacement_gc AFTER UPDATE OF set_id ON dependency_evidence_selections
WHEN OLD.set_id != NEW.set_id
BEGIN
    DELETE FROM dependency_evidence_sets WHERE set_id=OLD.set_id
        AND NOT EXISTS(SELECT 1 FROM dependency_evidence_selections WHERE set_id=OLD.set_id);
END;

-- Coordinates and anchors are derived from the exact selected bytes at
-- publication, including private overlays. Query execution does not reread files.
CREATE TABLE dependency_file_locations (
    set_id INTEGER NOT NULL,
    id TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    start_column INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    end_column INTEGER NOT NULL,
    slice_sha256 BLOB NOT NULL CHECK(length(slice_sha256)=32),
    PRIMARY KEY(set_id,id),
    FOREIGN KEY(set_id,id) REFERENCES dependency_file_evidence(set_id,id) ON DELETE CASCADE
) WITHOUT ROWID;
