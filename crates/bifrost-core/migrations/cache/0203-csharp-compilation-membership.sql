-- C# compilation membership derived from one revision's MSBuild configuration
-- inputs (.csproj, .props, .targets). A set is shared by every revision whose
-- ordered configuration paths and contents, and derivation version, agree.
-- Rows state membership rules, not member lists: a reader evaluates them per
-- demand against the revision's selected source rows, so a source edit reuses
-- the set.
CREATE TABLE csharp_compilation_sets (
    set_id INTEGER PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    lang TEXT NOT NULL CHECK(lang = 'csharp'),
    generation INTEGER NOT NULL,
    derivation_version INTEGER NOT NULL CHECK(derivation_version > 0),
    input_digest BLOB NOT NULL CHECK(length(input_digest) = 32),
    -- Digest of the rule rows below, for early cutoff by dependents.
    output_digest BLOB NOT NULL CHECK(length(output_digest) = 32),
    -- 1 only when every configuration input was read and every project states
    -- its Compile items in supported static shapes, so the rules below are
    -- all of the configuration's source membership.
    membership_complete INTEGER NOT NULL CHECK(membership_complete IN (0,1)),
    -- Positional [code, path, evidence] triples; read whole for diagnostics.
    gaps BLOB NOT NULL CHECK(json_valid(gaps, 8)),
    UNIQUE(workspace_id, lang, generation, derivation_version, input_digest)
);

CREATE TABLE csharp_compilation_selections (
    workspace_id TEXT NOT NULL,
    lang TEXT NOT NULL,
    generation INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    set_id INTEGER NOT NULL REFERENCES csharp_compilation_sets(set_id) ON DELETE CASCADE,
    PRIMARY KEY(workspace_id, lang, generation, revision),
    FOREIGN KEY(workspace_id, lang, generation, revision)
        REFERENCES workspace_revisions(workspace_id, lang, generation, revision) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE INDEX idx_csharp_compilation_selections_set ON csharp_compilation_selections(set_id);

-- A revision deletion also reclaims a set no other revision selects.
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

-- One compilation per project file. A configuration with no project has one
-- implicit compilation (project_path NULL) holding every selected source.
CREATE TABLE csharp_compilations (
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
    UNIQUE(set_id, project_path)
);
-- Compile items with static workspace paths, in evaluation order: an exact
-- include or remove of one file, an include of every C# source below a
-- directory (`<dir>/**/*.cs`), or the SDK default Compile glob of the
-- project directory, which also leaves out its hidden directories
-- (`**/.*/**`). The last item claiming a path decides it.
CREATE TABLE csharp_compilation_items (
    compilation_id INTEGER NOT NULL REFERENCES csharp_compilations(compilation_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    set_id INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('include', 'remove', 'include_tree', 'default_tree')),
    rel_path TEXT NOT NULL,
    -- For a tree, a JSONB array of directories it leaves out (an Exclude, or
    -- the SDK's build output roots); read whole by the one reader that
    -- evaluates the item.
    excluded_trees BLOB CHECK(
        (kind IN ('include_tree', 'default_tree')) = (excluded_trees IS NOT NULL)
        AND (excluded_trees IS NULL OR json_valid(excluded_trees, 8))
    ),
    PRIMARY KEY(compilation_id, ordinal)
) WITHOUT ROWID;
-- Items naming one source path, and the include inventory of one set.
CREATE INDEX idx_csharp_compilation_items_path
    ON csharp_compilation_items(set_id, rel_path, compilation_id, ordinal);

-- Proven direct ProjectReference edges: an item whose metadata could change
-- whether or how the reference reaches the project publishes no edge, and a
-- project that removes, updates or defines defaults for its references
-- publishes none.
-- Readers walk edges transitively only through projects with transitive_flow.
CREATE TABLE csharp_project_references (
    from_compilation_id INTEGER NOT NULL
        REFERENCES csharp_compilations(compilation_id) ON DELETE CASCADE,
    target_compilation_id INTEGER NOT NULL
        REFERENCES csharp_compilations(compilation_id) ON DELETE CASCADE,
    PRIMARY KEY(from_compilation_id, target_compilation_id)
) WITHOUT ROWID;
