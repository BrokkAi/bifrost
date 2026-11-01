-- Existing sets are derivation v4 and cannot satisfy the v5 selection contract.
ALTER TABLE csharp_compilations ADD COLUMN inventory_open
 -- Whether unmodeled declarations or source-item effects leave this inventory open.
 INTEGER NOT NULL DEFAULT 0 CHECK(inventory_open IN (0,1));
-- Ordinals into this compilation set's canonical gaps array, not copies of text.
ALTER TABLE csharp_compilations ADD COLUMN inventory_gap_indices
 -- Ordinals into the selected set canonical gaps array; never copied gap text.
 BLOB NOT NULL DEFAULT X'0B'
 CHECK(json_valid(inventory_gap_indices,8) AND json_type(inventory_gap_indices)='array'
  AND (inventory_open=1 OR json_array_length(inventory_gap_indices)=0));
UPDATE csharp_compilations SET inventory_open=1;

CREATE TABLE csharp_compilation_items_new (
 compilation_id INTEGER NOT NULL REFERENCES csharp_compilations(compilation_id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL CHECK(ordinal>=0),
 set_id INTEGER NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('include','remove','include_tree','default_tree','open','open_tree')),
 rel_path TEXT NOT NULL,
 -- Positional workspace-relative trees excluded from this tree rule.
 excluded_trees BLOB CHECK(
  (kind IN ('include_tree','default_tree','open_tree'))=(excluded_trees IS NOT NULL)
  AND (excluded_trees IS NULL OR json_valid(excluded_trees,8))),
 -- Ordinals into csharp_compilation_sets.gaps; the set stores each gap once.
 gap_indices BLOB NOT NULL DEFAULT X'0B' CHECK(json_valid(gap_indices,8)
  AND json_type(gap_indices)='array'
  AND ((kind IN ('open','open_tree'))=(json_array_length(gap_indices)>0))),
 PRIMARY KEY(compilation_id,ordinal)
) WITHOUT ROWID;
INSERT INTO csharp_compilation_items_new(compilation_id,ordinal,set_id,kind,rel_path,excluded_trees)
 SELECT compilation_id,ordinal,set_id,kind,rel_path,excluded_trees FROM csharp_compilation_items;
-- There are no children of the item rows. Foreign keys are OFF in migrate().
DROP TABLE csharp_compilation_items;
ALTER TABLE csharp_compilation_items_new RENAME TO csharp_compilation_items;
CREATE INDEX idx_csharp_compilation_items_path ON csharp_compilation_items(set_id,rel_path,compilation_id,ordinal);
-- Selection GC triggers reference this parent and must be suspended for the swap.
DROP TRIGGER csharp_compilation_selection_gc;
DROP TRIGGER csharp_compilation_selection_replacement_gc;
-- FKs are OFF in migrate(); child FK names
-- continue to name csharp_compilation_sets after the replacement is renamed.
CREATE TABLE csharp_compilation_sets_new (
    set_id INTEGER PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    lang TEXT NOT NULL CHECK(lang = 'csharp'),
    generation INTEGER NOT NULL,
    derivation_version INTEGER NOT NULL CHECK(derivation_version > 0),
    input_digest BLOB NOT NULL CHECK(length(input_digest) = 32),
    -- Digest of the rule rows below, for early cutoff by dependents.
    output_digest BLOB NOT NULL CHECK(length(output_digest) = 32),
    -- Positional [code, path, evidence] triples; read whole for diagnostics.
    gaps BLOB NOT NULL CHECK(json_valid(gaps, 8)),
    UNIQUE(workspace_id, lang, generation, derivation_version, input_digest)
);
INSERT INTO csharp_compilation_sets_new
 (set_id,workspace_id,lang,generation,derivation_version,input_digest,output_digest,gaps)
 SELECT set_id,workspace_id,lang,generation,derivation_version,input_digest,output_digest,gaps
 FROM csharp_compilation_sets;
DROP TABLE csharp_compilation_sets;
ALTER TABLE csharp_compilation_sets_new RENAME TO csharp_compilation_sets;
CREATE VIEW csharp_compilation_membership_coverage AS
 SELECT compilation.compilation_id, compilation.set_id,
 NOT EXISTS(SELECT 1 FROM csharp_compilation_items item
  WHERE item.compilation_id=compilation.compilation_id AND item.kind IN ('open','open_tree')) AS membership_complete
 FROM csharp_compilations compilation;

CREATE TRIGGER csharp_compilation_selection_gc AFTER DELETE ON csharp_compilation_selections
BEGIN
    DELETE FROM csharp_compilation_sets WHERE set_id = OLD.set_id
        AND NOT EXISTS(SELECT 1 FROM csharp_compilation_selections WHERE set_id = OLD.set_id);
END;
CREATE TRIGGER csharp_compilation_selection_replacement_gc
AFTER UPDATE OF set_id ON csharp_compilation_selections
WHEN OLD.set_id != NEW.set_id
BEGIN
    DELETE FROM csharp_compilation_sets WHERE set_id = OLD.set_id
        AND NOT EXISTS(SELECT 1 FROM csharp_compilation_selections WHERE set_id = OLD.set_id);
END;
