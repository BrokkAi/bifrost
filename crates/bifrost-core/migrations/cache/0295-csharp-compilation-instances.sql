-- Compatible: version-suffixed store files exclude mixed-version writers.
-- The UNIQUE rebuild preserves compilation IDs and child rows while allowing
-- distinct target-framework instances of the same project in one set.
-- Foreign keys are disabled by migrate(); keep all child rows while replacing the parent.
DROP VIEW csharp_compilation_membership_coverage;
CREATE TABLE csharp_compilations_new (
    compilation_id INTEGER PRIMARY KEY,
    set_id INTEGER NOT NULL REFERENCES csharp_compilation_sets(set_id) ON DELETE CASCADE,
    project_path TEXT,
    -- 1 only when the edges below are all of this project's direct
    -- references: every ProjectReference resolved to a compilation in this
    -- set and no unsupported reference shape or metadata appeared.
    references_complete INTEGER NOT NULL CHECK(references_complete IN (0,1)),
    -- 1 only when this project is an SDK project that receives its
    -- references' references by the SDK default, so its edges may be walked
    -- transitively.
    transitive_flow INTEGER NOT NULL CHECK(transitive_flow IN (0,1)),
    -- NULL means the name is not statically known, or this is a loose compilation.
    assembly_name TEXT,
    global_usings_complete INTEGER NOT NULL CHECK(global_usings_complete IN (0,1)),
    internals_visible_to_complete INTEGER NOT NULL CHECK(internals_visible_to_complete IN (0,1)),
    -- Read whole for one compilation: positional [kind, segments, alias, origin]
    -- entries. Segments is a string array; alias is a string or null.
    -- No identity references or separately constrained values live in this array.
    global_usings BLOB NOT NULL CHECK(json_valid(global_usings, 8)),
    -- Read whole for one compilation: an ordered array of friend assembly names.
    internals_visible_to BLOB NOT NULL CHECK(json_valid(internals_visible_to, 8)), configuration TEXT NOT NULL DEFAULT 'Debug', target_framework TEXT, symbols_closed INTEGER NOT NULL DEFAULT 0 CHECK(symbols_closed IN (0,1)), open_reason TEXT DEFAULT 'unrestored'
 CHECK ((symbols_closed = 1 AND open_reason IS NULL) OR
        (symbols_closed = 0 AND open_reason IS NOT NULL AND open_reason IN ('loose_files','unrestored','condition','dynamic_property','unevaluated_import','package_build_import','unsupported_framework','unknown_configuration_presence','target_assignment','dynamic_target_property','treat_as_local_property'))), symbol_set_digest BLOB CHECK(length(symbol_set_digest) = 32), inventory_open
 -- Whether unmodeled declarations or source-item effects leave this inventory open.
 INTEGER NOT NULL DEFAULT 0 CHECK(inventory_open IN (0,1)), inventory_gap_indices
 -- Ordinals into the selected set canonical gaps array; never copied gap text.
 BLOB NOT NULL DEFAULT X'0B'
 CHECK(json_valid(inventory_gap_indices,8) AND json_type(inventory_gap_indices)='array'
  AND (inventory_open=1 OR json_array_length(inventory_gap_indices)=0)),
    UNIQUE(set_id, project_path, target_framework)
);
INSERT INTO csharp_compilations_new (compilation_id, set_id, project_path, references_complete, transitive_flow, assembly_name, global_usings_complete, internals_visible_to_complete, global_usings, internals_visible_to, configuration, target_framework, symbols_closed, open_reason, symbol_set_digest, inventory_open, inventory_gap_indices)
 SELECT compilation_id, set_id, project_path, references_complete, transitive_flow, assembly_name, global_usings_complete, internals_visible_to_complete, global_usings, internals_visible_to, configuration, target_framework, symbols_closed, open_reason, symbol_set_digest, inventory_open, inventory_gap_indices FROM csharp_compilations;
DROP TABLE csharp_compilations;
ALTER TABLE csharp_compilations_new RENAME TO csharp_compilations;
CREATE VIEW csharp_compilation_membership_coverage AS
 SELECT compilation.compilation_id, compilation.set_id,
 NOT EXISTS(SELECT 1 FROM csharp_compilation_items item
  WHERE item.compilation_id=compilation.compilation_id AND item.kind IN ('open','open_tree')) AS membership_complete
 FROM csharp_compilations compilation;

-- Stream one set's instances and their symbols in compilation identity order.
CREATE INDEX idx_csharp_compilations_set_instance
 ON csharp_compilations(set_id, compilation_id);
