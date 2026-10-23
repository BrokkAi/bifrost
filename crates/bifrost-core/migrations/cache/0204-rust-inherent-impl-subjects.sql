-- #6394: subject-only headers retain source declaration authority while the
-- lowering still borrows canonical source facts. NULL is an unbridged input,
-- never a resolved impl whose members may be silently dropped.
ALTER TABLE resolution_fragment_interiors ADD COLUMN
  expected_inherent_implementation_count INTEGER NOT NULL DEFAULT 0
  CHECK(expected_inherent_implementation_count >= 0);

CREATE TABLE resolution_inherent_implementations(
  blob_id INTEGER NOT NULL,
  relation_key INTEGER NOT NULL CHECK(relation_key >= 0),
  position INTEGER NOT NULL CHECK(position >= 0),
  segment TEXT,
  terminal_spelling TEXT,
  impl_site INTEGER NOT NULL CHECK(impl_site BETWEEN 0 AND 4294967295),
  impl_start_byte INTEGER NOT NULL CHECK(impl_start_byte >= 0),
  impl_end_byte INTEGER NOT NULL CHECK(impl_end_byte >= impl_start_byte),
  impl_declaration_id INTEGER
    CHECK(impl_declaration_id IS NULL OR impl_declaration_id BETWEEN 0 AND 4294967295),
  PRIMARY KEY(blob_id, relation_key, position),
  CHECK(segment IS NULL OR terminal_spelling IS NULL),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE rust_crate_inherent_impls(
  topology_id INTEGER NOT NULL,
  subject_declaration_blob_id INTEGER NOT NULL,
  subject_declaration_site INTEGER NOT NULL
    CHECK(subject_declaration_site BETWEEN 0 AND 4294967295),
  subject_rel_path TEXT NOT NULL CHECK(length(subject_rel_path) > 0),
  impl_blob_id INTEGER NOT NULL,
  -- A resolution reference site, distinct from the impl's source declaration.
  impl_site INTEGER NOT NULL CHECK(impl_site BETWEEN 0 AND 4294967295),
  impl_rel_path TEXT NOT NULL CHECK(length(impl_rel_path) > 0),
  impl_declaration_id INTEGER NOT NULL CHECK(impl_declaration_id BETWEEN 0 AND 4294967295),
  PRIMARY KEY(topology_id, subject_declaration_blob_id, subject_declaration_site,
              subject_rel_path, impl_blob_id, impl_site, impl_rel_path),
  FOREIGN KEY(topology_id) REFERENCES rust_crate_topologies(topology_id) ON DELETE CASCADE,
  FOREIGN KEY(subject_declaration_blob_id) REFERENCES blobs(id),
  FOREIGN KEY(impl_blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- The point reader asks for one resolved declaration AND its placement.
CREATE INDEX rust_crate_inherent_impls_subject ON rust_crate_inherent_impls(
  subject_declaration_blob_id, subject_declaration_site, subject_rel_path,
  topology_id, impl_blob_id, impl_site, impl_rel_path, impl_declaration_id
);
CREATE INDEX rust_crate_inherent_impls_impl ON rust_crate_inherent_impls(impl_blob_id);

CREATE TABLE rust_crate_unresolved_inherent_impls(
  topology_id INTEGER NOT NULL,
  -- Unsupported/unpositioned subjects need not have a nominal spelling.
  spelling TEXT CHECK(spelling IS NULL OR length(spelling) > 0),
  impl_blob_id INTEGER NOT NULL,
  impl_site INTEGER NOT NULL CHECK(impl_site BETWEEN 0 AND 4294967295),
  impl_rel_path TEXT NOT NULL CHECK(length(impl_rel_path) > 0),
  impl_declaration_id INTEGER
    CHECK(impl_declaration_id IS NULL OR impl_declaration_id BETWEEN 0 AND 4294967295),
  reason TEXT NOT NULL CHECK(reason IN ('unbound', 'bound_without_declaration', 'impl_item_unbridged')),
  target_module_path TEXT CHECK(target_module_path IS NULL OR length(target_module_path) > 0),
  PRIMARY KEY(topology_id, impl_blob_id, impl_site, impl_rel_path, reason),
  FOREIGN KEY(topology_id) REFERENCES rust_crate_topologies(topology_id) ON DELETE CASCADE,
  FOREIGN KEY(impl_blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX rust_crate_unresolved_inherent_impls_impl
  ON rust_crate_unresolved_inherent_impls(impl_blob_id);

-- Shared by full and limited direct-children readers, and by later relations.
-- Readers must bind these rows to complete, selected workspace topologies.
CREATE VIEW rust_crate_impls_of_subject AS
SELECT topology_id, subject_declaration_blob_id, subject_declaration_site,
       subject_rel_path, impl_blob_id, impl_site, impl_rel_path, impl_declaration_id
FROM rust_crate_trait_impls
UNION ALL
SELECT topology_id, subject_declaration_blob_id, subject_declaration_site,
       subject_rel_path, impl_blob_id, impl_site, impl_rel_path, impl_declaration_id
FROM rust_crate_inherent_impls;
