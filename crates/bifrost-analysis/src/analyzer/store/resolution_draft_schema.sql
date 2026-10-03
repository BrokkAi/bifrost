-- The draft schema of `.agents/docs/stack-graph-schema-draft-2026-09-18.md`
-- exactly as lane LD loaded it, so milestone 6 starts from what was measured.
--
-- This file is read only by the ignored measurement test
-- `resolution_prepare::schema_loader`. No production code opens it.
--
-- How to read it:
--
-- * A line `-- @section <name>` starts a section. The loader concatenates the
--   sections a variant needs, in the order the variant lists them.
-- * A line whose first characters are `--+fk ` belongs to the foreign-key
--   variant only. The loader strips that prefix for that variant and drops the
--   line for every other variant. SQLite cannot add a foreign key to an
--   existing table, so the alternative was a second hand-maintained copy of
--   forty tables; one table list that cannot drift is worth the marker.
-- * Enumeration columns are INTEGER codes in the `draft` section: the code is
--   the value's declaration position in its `labelled_enum!` vocabulary. The
--   `enum_text` and `enum_code` sections load the two largest
--   enumeration-bearing tables both ways so decision 3 has a number.
--
-- Deviations from the draft are listed in
-- `.agents/docs/stack-graph-schema-loader-2026-09-18.md`; each one is marked
-- `-- deviation:` at the column it affects.

-- @section core

CREATE TABLE resolution_identities (
  id                INTEGER PRIMARY KEY,
  identity_digest   BLOB NOT NULL UNIQUE,   -- 32 bytes
  semantic_language INTEGER,                -- NULL when the name is not a lookup recipe
  namespace         INTEGER,
  spelling          TEXT
) STRICT;

CREATE TABLE resolution_blob_facts (
  blob_id           INTEGER PRIMARY KEY,
  semantic_language INTEGER NOT NULL,
  producer_epoch    TEXT NOT NULL,
  facts_digest      BLOB NOT NULL,
  demand_rows       INTEGER NOT NULL DEFAULT 0 CHECK(demand_rows IN (0, 1))
) STRICT;

-- @section fk_parents

--+fk -- The three parents the composite intra-blob foreign keys need. No
--+fk -- reader in the question list asks for any of them; they exist so that a
--+fk -- child column can be declared a foreign key at all (owner decision 4,
--+fk -- measured).
--+fk CREATE TABLE resolution_semantics (
--+fk   blob_id      INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
--+fk   semantic_key INTEGER NOT NULL,
--+fk   PRIMARY KEY(blob_id, semantic_key)
--+fk ) WITHOUT ROWID, STRICT;
--+fk
--+fk CREATE TABLE resolution_nodes (
--+fk   blob_id  INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
--+fk   node_key INTEGER NOT NULL,
--+fk   kind     INTEGER NOT NULL,
--+fk   PRIMARY KEY(blob_id, node_key)
--+fk ) WITHOUT ROWID, STRICT;
--+fk
--+fk CREATE TABLE resolution_stack_variables (
--+fk   blob_id      INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
--+fk   variable_key INTEGER NOT NULL,
--+fk   PRIMARY KEY(blob_id, variable_key)
--+fk ) WITHOUT ROWID, STRICT;

-- @section draft

-- Section 3 of the draft. Written at index time.
CREATE TABLE resolution_sites (
  blob_id         INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  site            INTEGER NOT NULL,   -- ResolutionSiteId, dense per blob
  role            INTEGER NOT NULL,   -- 0 reference, 1 definition
  semantic        INTEGER NOT NULL,   -- local semantic key
  node            INTEGER NOT NULL,   -- local node key
  namespace       INTEGER NOT NULL,
  site_kind       INTEGER NOT NULL,
  start_byte      INTEGER NOT NULL,
  end_byte        INTEGER NOT NULL,
  unqualified     INTEGER NOT NULL,   -- references only; 0 for a definition
  -- deviation: local semantic key, -1 = the reference sits in no declaration,
  -- NULL = the producer published no ownership. A sentinel cannot carry a
  -- foreign key, so the foreign-key variant leaves this column unconstrained.
  owner           INTEGER,
  receiver_origin INTEGER,            -- NULL unless a callable reference
  PRIMARY KEY(blob_id, site)
--+fk   , FOREIGN KEY(blob_id, semantic) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, node) REFERENCES resolution_nodes(blob_id, node_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE UNIQUE INDEX resolution_sites_semantic
  ON resolution_sites(blob_id, role, semantic);

CREATE INDEX resolution_sites_range
  ON resolution_sites(blob_id, start_byte, end_byte, role);

CREATE INDEX resolution_sites_node
  ON resolution_sites(blob_id, node, role, semantic, site);

--+fk CREATE INDEX resolution_sites_fk_semantic ON resolution_sites(blob_id, semantic);

-- Section 4 of the draft. Written on first demand.
CREATE TABLE resolution_paths (
  blob_id             INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  path                INTEGER NOT NULL,  -- local path key
  start_node          INTEGER NOT NULL,  -- local node key; -1 = the universal root
  start_lead_local    INTEGER,
  start_lead_identity INTEGER REFERENCES resolution_identities(id),
  start_lead_scoped   INTEGER NOT NULL,
  end_node            INTEGER NOT NULL,
  end_lead_local      INTEGER,
  end_lead_identity   INTEGER REFERENCES resolution_identities(id),
  end_lead_scoped     INTEGER NOT NULL,
  -- deviation: the interned id, not minus the interned id. The sign in the
  -- draft carries no information in a column that holds nothing else.
  root_terminal       INTEGER REFERENCES resolution_identities(id),
  body                BLOB NOT NULL CHECK(json_valid(body, 8)),
  end_fixed_key       TEXT COLLATE BINARY,
  end_open_tail       INTEGER,
  -- deviation: the draft's CHECK((a IS NULL) <> (b IS NULL)) forbids the case
  -- its own comment documents, an endpoint that fixes no symbol. At most one.
  CHECK(start_lead_local IS NULL OR start_lead_identity IS NULL),
  CHECK(end_lead_local IS NULL OR end_lead_identity IS NULL),
  CHECK((end_node = -1 AND end_fixed_key IS NOT NULL
         AND end_open_tail IS NOT NULL AND end_open_tail IN (0, 1))
     OR (end_node <> -1 AND end_fixed_key IS NULL AND end_open_tail IS NULL)),
  CHECK(end_fixed_key IS NULL OR (
    json_valid(end_fixed_key) AND json_type(end_fixed_key) = 'array'
    AND json(end_fixed_key) = end_fixed_key
    AND json_type(body, '$[4]') = 'array'
    AND json_array_length(end_fixed_key) = json_array_length(body, '$[4]')
    AND json_type(body, '$[5]') IN ('null', 'integer')
    AND end_open_tail = (json_type(body, '$[5]') = 'integer')
  ) IS TRUE),
  PRIMARY KEY(blob_id, path)
--+fk   , FOREIGN KEY(blob_id, start_node) REFERENCES resolution_nodes(blob_id, node_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, end_node) REFERENCES resolution_nodes(blob_id, node_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, start_lead_local) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, end_lead_local) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_paths_forward
  ON resolution_paths(blob_id, start_node, start_lead_identity, start_lead_local, start_lead_scoped, path);

CREATE INDEX resolution_paths_reverse
  ON resolution_paths(blob_id, end_node, end_lead_identity, end_lead_local, end_lead_scoped, path);

CREATE INDEX resolution_paths_reverse_root_prefix
  ON resolution_paths(blob_id, end_fixed_key COLLATE BINARY, end_open_tail, path)
  WHERE end_node = -1;

CREATE INDEX resolution_paths_root_terminal
  ON resolution_paths(blob_id, root_terminal, path) WHERE root_terminal IS NOT NULL;

CREATE TRIGGER resolution_paths_validate_root_prefix_insert
BEFORE INSERT ON resolution_paths
WHEN NEW.end_node = -1 AND (EXISTS (
       SELECT 1 FROM json_each(NEW.end_fixed_key) AS cell
       WHERE CASE WHEN cell.type <> 'array' THEN 1
         WHEN json_array_length(cell.value) <> 3 THEN 1
         ELSE (
           ((json_type(cell.value, '$[0]') = 'integer'
             AND cell.value ->> 0 >= 0 AND json_type(cell.value, '$[1]') = 'null')
            OR (json_type(cell.value, '$[0]') = 'null'
             AND json_type(cell.value, '$[1]') = 'integer' AND cell.value ->> 1 > 0)) IS NOT TRUE
           OR (json_type(cell.value, '$[2]') = 'integer' AND cell.value ->> 2 IN (0, 1)) IS NOT TRUE
         ) END
     ) OR NEW.end_fixed_key <> (
       SELECT json_group_array(json(canonical_cell)) FROM (
         SELECT json_array(
           CASE WHEN signed >= 0 THEN signed ELSE NULL END,
           CASE WHEN signed < 0 THEN -signed ELSE NULL END,
           scoped) AS canonical_cell
         FROM (
           SELECT symbol.key AS ordinal,
             CASE WHEN symbol.type = 'integer' THEN symbol.value
               WHEN symbol.type = 'array' THEN
                 CASE WHEN json_type(symbol.value, '$[0]') = 'integer'
                   THEN symbol.value ->> 0 ELSE NULL END
               ELSE NULL END AS signed,
             symbol.type = 'array' AS scoped
           FROM json_each(NEW.body, '$[4]') AS symbol
         ) ORDER BY ordinal
       )
     ))
BEGIN
  SELECT RAISE(ABORT, 'resolution root prefix key is inconsistent');
END;

--+fk CREATE INDEX resolution_paths_fk_start_lead ON resolution_paths(blob_id, start_lead_local);
--+fk CREATE INDEX resolution_paths_fk_end_lead ON resolution_paths(blob_id, end_lead_local);

-- Section 5 of the draft. `covers` 0 to 3 and the root-rooted 5 and 6 rows are
-- written at index time; the rest on first demand. The loader writes them all.
CREATE TABLE resolution_gaps (
  blob_id         INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  covers          INTEGER NOT NULL,
  -- deviation: polymorphic. covers 4 and 7 hold a local semantic, 5 and 6 a
  -- node key (-1 = root), 0 to 3 hold 0. No foreign key can be declared on it.
  subject         INTEGER NOT NULL,
  -- deviation: 0 = every lookup, a positive value is local semantic key + 1,
  -- a negative value is minus the interned id. The draft's "signed semantic,
  -- 0 = every lookup" collides with local semantic key 0, which exists.
  lookup          INTEGER NOT NULL,
  gap             INTEGER NOT NULL,
  reason_kind     INTEGER NOT NULL,
  reason          INTEGER NOT NULL,
  boundary_status INTEGER,
  site            INTEGER NOT NULL,
  origin          INTEGER NOT NULL,
  PRIMARY KEY(blob_id, covers, subject, lookup, gap)
--+fk   , FOREIGN KEY(blob_id, reason) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_gaps_reason ON resolution_gaps(blob_id, reason, site, origin);

-- Section 6 of the draft: one table per typed fact type.

CREATE TABLE resolution_type_frontiers (
  blob_id INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  slot INTEGER NOT NULL,
  role INTEGER NOT NULL,
  identity_reference INTEGER, identity_node INTEGER,
  PRIMARY KEY(blob_id, slot)
--+fk   , FOREIGN KEY(blob_id, slot) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, identity_reference) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, identity_node) REFERENCES resolution_nodes(blob_id, node_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_type_frontiers_reference
  ON resolution_type_frontiers(blob_id, identity_reference) WHERE identity_reference IS NOT NULL;

--+fk CREATE INDEX resolution_type_frontiers_fk_reference ON resolution_type_frontiers(blob_id, identity_reference);
--+fk CREATE INDEX resolution_type_frontiers_fk_node ON resolution_type_frontiers(blob_id, identity_node);

CREATE TABLE resolution_type_transfers (
  blob_id INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  source_slot INTEGER NOT NULL, rule INTEGER NOT NULL,
  target_slot INTEGER NOT NULL, kind INTEGER NOT NULL,
  indirection_delta INTEGER NOT NULL, reference_indirection_delta INTEGER NOT NULL,
  value_transform INTEGER NOT NULL,
  completion BLOB CHECK(completion IS NULL OR json_valid(completion, 8)),
  PRIMARY KEY(blob_id, source_slot, rule)
--+fk   , FOREIGN KEY(blob_id, source_slot) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, rule) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, target_slot) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_type_transfers_target
  ON resolution_type_transfers(blob_id, target_slot, source_slot, rule);

CREATE TABLE resolution_type_components (
  blob_id INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  container_slot INTEGER NOT NULL,
  constructor INTEGER NOT NULL CHECK(constructor IN (0,1,2)),
  kind INTEGER NOT NULL CHECK(kind IN (0,1,2)),
  component_slot INTEGER NOT NULL,
  PRIMARY KEY(blob_id, container_slot, kind),
  CHECK((constructor IN (0,2) AND kind=0) OR (constructor=1 AND kind IN (1,2)))
--+fk   , FOREIGN KEY(blob_id, container_slot) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, component_slot) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_type_components_component
  ON resolution_type_components(blob_id, component_slot, container_slot);

CREATE TABLE resolution_underlying_types (
  blob_id INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  definition INTEGER NOT NULL,
  slot INTEGER NOT NULL,
  PRIMARY KEY(blob_id, definition)
--+fk   , FOREIGN KEY(blob_id, definition) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, slot) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_underlying_types_slot
  ON resolution_underlying_types(blob_id, slot, definition);

--+fk CREATE INDEX resolution_type_transfers_fk_rule ON resolution_type_transfers(blob_id, rule);

CREATE TABLE resolution_intrinsic_seeds (
  blob_id INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  slot INTEGER NOT NULL,
  kind INTEGER NOT NULL,
  spelling TEXT NOT NULL,
  -- [[category, identity, indirection, reference_indirection, addressable], ...]
  possible_values BLOB NOT NULL CHECK(json_valid(possible_values, 8)),
  completion BLOB CHECK(completion IS NULL OR json_valid(completion, 8)),
  PRIMARY KEY(blob_id, slot)
--+fk   , FOREIGN KEY(blob_id, slot) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE TABLE resolution_intrinsic_seed_identities (
  blob_id INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  identity_id INTEGER NOT NULL REFERENCES resolution_identities(id),
  slot INTEGER NOT NULL,
  PRIMARY KEY(blob_id, identity_id, slot)
--+fk   , FOREIGN KEY(blob_id, slot) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

--+fk CREATE INDEX resolution_intrinsic_seed_identities_fk_slot
--+fk   ON resolution_intrinsic_seed_identities(blob_id, slot);

CREATE TABLE resolution_binding_projections (
  blob_id INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  reference INTEGER NOT NULL, output_slot INTEGER NOT NULL,
  kind INTEGER NOT NULL,
  PRIMARY KEY(blob_id, reference, output_slot)
--+fk   , FOREIGN KEY(blob_id, reference) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, output_slot) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_binding_projections_output
  ON resolution_binding_projections(blob_id, output_slot, reference);

CREATE TABLE resolution_qualified_routes (
  blob_id INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  reference INTEGER NOT NULL, precedence_ordinal INTEGER NOT NULL,
  qualifier_slot INTEGER NOT NULL,
  lookup INTEGER NOT NULL REFERENCES resolution_identities(id),
  source_lookup INTEGER NOT NULL REFERENCES resolution_identities(id),
  namespace INTEGER NOT NULL,
  projection_output_slot INTEGER NOT NULL, projection_kind INTEGER NOT NULL,
  coarse_gap_reason INTEGER NOT NULL,
  PRIMARY KEY(blob_id, reference, precedence_ordinal, projection_output_slot)
--+fk   , FOREIGN KEY(blob_id, reference) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, qualifier_slot) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, projection_output_slot) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, coarse_gap_reason) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_qualified_routes_slot
  ON resolution_qualified_routes(blob_id, qualifier_slot, lookup, reference, precedence_ordinal);

CREATE INDEX resolution_qualified_routes_gap
  ON resolution_qualified_routes(blob_id, coarse_gap_reason, reference, precedence_ordinal);

--+fk CREATE INDEX resolution_qualified_routes_fk_projection
--+fk   ON resolution_qualified_routes(blob_id, projection_output_slot);

CREATE TABLE resolution_declaration_types (
  blob_id INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  definition INTEGER NOT NULL, role INTEGER NOT NULL, slot INTEGER NOT NULL,
  PRIMARY KEY(blob_id, definition, role, slot)
--+fk   , FOREIGN KEY(blob_id, definition) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, slot) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_declaration_types_slot
  ON resolution_declaration_types(blob_id, slot, definition, role);

CREATE TABLE resolution_member_scopes (
  blob_id INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  definition INTEGER NOT NULL, scope_head INTEGER NOT NULL,
  PRIMARY KEY(blob_id, definition)
--+fk   , FOREIGN KEY(blob_id, definition) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, scope_head) REFERENCES resolution_nodes(blob_id, node_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE UNIQUE INDEX resolution_member_scopes_head ON resolution_member_scopes(blob_id, scope_head);

CREATE TABLE resolution_member_owners (
  blob_id INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  definition INTEGER NOT NULL, owner_definition INTEGER NOT NULL,
  owner_scope_head INTEGER NOT NULL, kind INTEGER NOT NULL, access INTEGER NOT NULL,
  qualifier_compatibility INTEGER NOT NULL,
  PRIMARY KEY(blob_id, definition, owner_definition)
--+fk   , FOREIGN KEY(blob_id, definition) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, owner_definition) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, owner_scope_head) REFERENCES resolution_nodes(blob_id, node_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_member_owners_owner
  ON resolution_member_owners(blob_id, owner_definition, definition);

--+fk CREATE INDEX resolution_member_owners_fk_scope_head
--+fk   ON resolution_member_owners(blob_id, owner_scope_head);

CREATE TABLE resolution_deferred_member_owners (
  blob_id INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  definition INTEGER NOT NULL, seq INTEGER NOT NULL,
  lookup INTEGER NOT NULL REFERENCES resolution_identities(id),
  -- [owner_frontier, hierarchy_frontier, kind, access, qualifier_compatibility]
  body BLOB NOT NULL CHECK(json_valid(body, 8)),
  PRIMARY KEY(blob_id, definition, seq)
--+fk   , FOREIGN KEY(blob_id, definition) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE TABLE resolution_construction_requirements (
  blob_id INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  definition INTEGER NOT NULL, required_owner_definition INTEGER NOT NULL,
  kind INTEGER NOT NULL,
  PRIMARY KEY(blob_id, definition, required_owner_definition, kind)
--+fk   , FOREIGN KEY(blob_id, definition) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, required_owner_definition) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

--+fk CREATE INDEX resolution_construction_requirements_fk_owner
--+fk   ON resolution_construction_requirements(blob_id, required_owner_definition);

CREATE TABLE resolution_supertypes (
  blob_id INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  definition INTEGER NOT NULL, reference INTEGER NOT NULL,
  frontier INTEGER NOT NULL, kind INTEGER NOT NULL,
  PRIMARY KEY(blob_id, definition, reference)
--+fk   , FOREIGN KEY(blob_id, definition) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, reference) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, frontier) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_supertypes_reference ON resolution_supertypes(blob_id, reference, definition);
CREATE INDEX resolution_supertypes_frontier  ON resolution_supertypes(blob_id, frontier, definition, reference);

CREATE TABLE resolution_definition_property_gaps (
  blob_id INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  definition INTEGER NOT NULL, seq INTEGER NOT NULL,
  kind INTEGER NOT NULL, frontier INTEGER NOT NULL, reason INTEGER NOT NULL, site INTEGER NOT NULL,
  PRIMARY KEY(blob_id, definition, seq)
--+fk   , FOREIGN KEY(blob_id, definition) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, frontier) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, reason) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

--+fk CREATE INDEX resolution_definition_property_gaps_fk_frontier
--+fk   ON resolution_definition_property_gaps(blob_id, frontier);
--+fk CREATE INDEX resolution_definition_property_gaps_fk_reason
--+fk   ON resolution_definition_property_gaps(blob_id, reason);

CREATE TABLE resolution_call_obligations (
  blob_id INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  callee_reference INTEGER NOT NULL,
  call INTEGER NOT NULL, receiver_slot INTEGER, result_slot INTEGER NOT NULL,
  explicit_type_argument_count INTEGER NOT NULL,
  applicability_reason INTEGER NOT NULL,
  argument_slots BLOB NOT NULL CHECK(json_valid(argument_slots, 8)),
  type_argument_slots BLOB NOT NULL CHECK(json_valid(type_argument_slots, 8)),
  eligible_rules BLOB NOT NULL CHECK(json_valid(eligible_rules, 8)),
  completion BLOB CHECK(completion IS NULL OR json_valid(completion, 8)),
  PRIMARY KEY(blob_id, callee_reference)
--+fk   , FOREIGN KEY(blob_id, callee_reference) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, call) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, receiver_slot) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, result_slot) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
--+fk   , FOREIGN KEY(blob_id, applicability_reason) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_call_obligations_reason
  ON resolution_call_obligations(blob_id, applicability_reason, callee_reference);

--+fk CREATE INDEX resolution_call_obligations_fk_call ON resolution_call_obligations(blob_id, call);
--+fk CREATE INDEX resolution_call_obligations_fk_receiver ON resolution_call_obligations(blob_id, receiver_slot);
--+fk CREATE INDEX resolution_call_obligations_fk_result ON resolution_call_obligations(blob_id, result_slot);

CREATE TABLE resolution_callable_signatures (
  blob_id INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  definition INTEGER NOT NULL,
  -- [type_parameter_count, [[definition, slot, repeated], ...], completion]
  body BLOB NOT NULL CHECK(json_valid(body, 8)),
  PRIMARY KEY(blob_id, definition)
--+fk   , FOREIGN KEY(blob_id, definition) REFERENCES resolution_semantics(blob_id, semantic_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

-- @section enum_code

-- Decision 3, arm A: the two largest enumeration-bearing tables with integer
-- codes, alone in their own database so dbstat is not confounded.
CREATE TABLE resolution_sites (
  blob_id         INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  site            INTEGER NOT NULL,
  role            INTEGER NOT NULL,
  semantic        INTEGER NOT NULL,
  node            INTEGER NOT NULL,
  namespace       INTEGER NOT NULL,
  site_kind       INTEGER NOT NULL,
  start_byte      INTEGER NOT NULL,
  end_byte        INTEGER NOT NULL,
  unqualified     INTEGER NOT NULL,
  owner           INTEGER,
  receiver_origin INTEGER,
  PRIMARY KEY(blob_id, site)
) WITHOUT ROWID, STRICT;

CREATE UNIQUE INDEX resolution_sites_semantic ON resolution_sites(blob_id, role, semantic);
CREATE INDEX resolution_sites_range ON resolution_sites(blob_id, start_byte, end_byte, role);
CREATE INDEX resolution_sites_node ON resolution_sites(blob_id, node, role, semantic, site);

CREATE TABLE resolution_gaps (
  blob_id         INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  covers          INTEGER NOT NULL,
  subject         INTEGER NOT NULL,
  lookup          INTEGER NOT NULL,
  gap             INTEGER NOT NULL,
  reason_kind     INTEGER NOT NULL,
  reason          INTEGER NOT NULL,
  boundary_status INTEGER,
  site            INTEGER NOT NULL,
  origin          INTEGER NOT NULL,
  PRIMARY KEY(blob_id, covers, subject, lookup, gap)
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_gaps_reason ON resolution_gaps(blob_id, reason, site, origin);

-- @section enum_text

-- Decision 3, arm B: the same two tables with the text labels the vocabulary
-- macros already publish, and the CHECK(col IN (...)) the decision names. The
-- label lists are written out because a CHECK cannot read a Rust vocabulary.
CREATE TABLE resolution_sites (
  blob_id         INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  site            INTEGER NOT NULL,
  role            TEXT NOT NULL CHECK(role IN ('reference', 'definition')),
  semantic        INTEGER NOT NULL,
  node            INTEGER NOT NULL,
  namespace       TEXT NOT NULL CHECK(namespace IN (
                    'type', 'value', 'callable', 'constructor', 'macro', 'constant',
                    'type_or_value')),
  site_kind       TEXT NOT NULL CHECK(site_kind IN (
                    'package_declaration', 'import_declaration', 'module_declaration',
                    'macro_declaration', 'type_alias_declaration', 'type_declaration',
                    'callable_declaration', 'constructor_declaration', 'value_declaration',
                    'initializer', 'type_reference', 'value_reference', 'callable_reference',
                    'constructor_reference', 'member_reference', 'module_reference',
                    'macro_reference', 'call', 'literal', 'unsupported_route',
                    'unsupported_declaration', 'unsupported_expression')),
  start_byte      INTEGER NOT NULL,
  end_byte        INTEGER NOT NULL,
  unqualified     INTEGER NOT NULL,
  owner           INTEGER,
  receiver_origin TEXT CHECK(receiver_origin IS NULL OR receiver_origin IN (
                    'implicit', 'current_instance', 'super', 'explicit_expression')),
  PRIMARY KEY(blob_id, site)
) WITHOUT ROWID, STRICT;

CREATE UNIQUE INDEX resolution_sites_semantic ON resolution_sites(blob_id, role, semantic);
CREATE INDEX resolution_sites_range ON resolution_sites(blob_id, start_byte, end_byte, role);
CREATE INDEX resolution_sites_node ON resolution_sites(blob_id, node, role, semantic, site);

CREATE TABLE resolution_gaps (
  blob_id         INTEGER NOT NULL REFERENCES resolution_blob_facts(blob_id) ON DELETE CASCADE,
  covers          TEXT NOT NULL CHECK(covers IN (
                    'fragment', 'enumeration', 'forward_inventory', 'reverse_inventory',
                    'reference', 'forward_candidate', 'reverse_candidate', 'type_frontier')),
  subject         INTEGER NOT NULL,
  lookup          INTEGER NOT NULL,
  gap             INTEGER NOT NULL,
  reason_kind     TEXT NOT NULL CHECK(reason_kind IN (
                    'cyclic_expansion', 'inconsistent_precedence', 'open_boundary',
                    'unsupported_semantic')),
  reason          INTEGER NOT NULL,
  boundary_status TEXT CHECK(boundary_status IS NULL OR boundary_status IN (
                    'workspace_local', 'external_indexed', 'external_declared_unindexed',
                    'external_unknown')),
  site            INTEGER NOT NULL,
  origin          TEXT NOT NULL CHECK(origin IN (
                    'unsupported_type_syntax', 'unsupported_expression', 'unsupported_route',
                    'unsupported_scope_or_binder', 'ambiguous_qualified_type', 'inferred_type',
                    'postfix_array_dimensions', 'ambiguous_numeric_literal',
                    'implicit_constructor', 'unsupported_hierarchy_traversal',
                    'unsupported_visibility', 'unsupported_implicit_receiver',
                    'unsupported_call_applicability', 'unsupported_placement_boundary',
                    'malformed_syntax', 'qualified_reference',
                    'unsupported_activation_source_order', 'unsupported_activation_scope_wide',
                    'unsupported_activation_declared_head', 'missing_binder',
                    'unsupported_member_scope', 'unproven_activation',
                    'external_prelude_boundary')),
  PRIMARY KEY(blob_id, covers, subject, lookup, gap)
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_gaps_reason ON resolution_gaps(blob_id, reason, site, origin);
