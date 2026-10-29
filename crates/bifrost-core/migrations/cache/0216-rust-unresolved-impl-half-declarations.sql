-- Retain each resolved half's declaration at its impl placement.
-- Existing rows lack both declaration and owner-placement evidence. Discarding
-- this derived projection is safe: unresolved-impl-resolved-half-declarations-7226
-- changes every topology digest, so these rows are superseded and re-derived.
DROP TABLE rust_crate_unresolved_trait_impls;

CREATE TABLE rust_crate_unresolved_trait_impls (
  topology_id INTEGER NOT NULL,
  -- Which half of `impl Trait for Type` did not reach a declaration. Both
  -- halves are recorded: a reader asking whether a trait's implementations
  -- are enumerable wants the `trait` side, and one asking whether a type's
  -- implemented traits are wants `subject`.
  side TEXT NOT NULL CHECK(side IN ('subject', 'trait')),
  -- The head nominal name the unresolved side demanded, as written. This is
  -- the column the question is asked by: `rust_crate_gaps` already records
  -- the same evidence, but only inside its `detail` JSON keyed by module
  -- path, so asking "is anything spelled `Display` unbound here?" meant
  -- scanning and parsing every gap row.
  spelling TEXT NOT NULL CHECK(length(spelling) > 0),
  impl_blob_id INTEGER NOT NULL,
  impl_site INTEGER NOT NULL CHECK(impl_site BETWEEN 0 AND 4294967295),
  -- The file the crate places the impl in. Two byte-identical files are one
  -- blob, so without it an impl in either would send a reader to both.
  impl_rel_path TEXT NOT NULL CHECK(length(impl_rel_path) > 0),
  -- The impl item's source declaration, as `rust_crate_trait_impls` carries
  -- it; NULL when the bridge does not name exactly one impl item.
  impl_declaration_id INTEGER
    CHECK(impl_declaration_id IS NULL OR impl_declaration_id BETWEEN 0 AND 4294967295),
  -- `unbound` when no route bound this side at all, `bound_without_declaration`
  -- when a route bound a name whose declaration the derivation could not
  -- reach, and `resolved` when this side was fine and the impl is here because
  -- its other side was not. `owner_module_path`, not this column, keeps the
  -- verdicts of one impl placed in two modules apart.
  reason TEXT NOT NULL CHECK(reason IN ('unbound', 'bound_without_declaration', 'resolved')),
  -- The module the route reached, when it reached one.
  target_module_path TEXT CHECK(target_module_path IS NULL OR length(target_module_path) > 0),
  -- The declaration the `resolved` half reached, so the unit-summary writer can
  -- publish it by identity; NULL exactly when the half is not `resolved`.
  declaration_blob_id INTEGER,
  declaration_site INTEGER
    CHECK(declaration_site IS NULL OR declaration_site BETWEEN 0 AND 4294967295),
  declaration_rel_path TEXT
    CHECK(declaration_rel_path IS NULL OR length(declaration_rel_path) > 0),
  -- The placing module, not the module declaring the subject or trait. One file
  -- may be placed in two modules: one::W and two::W can include the same
  -- shared.rs containing an impl for W, with a different declaration per owner.
  owner_module_path TEXT NOT NULL CHECK(length(owner_module_path) > 0),
  CHECK((reason = 'resolved') = (declaration_blob_id IS NOT NULL)),
  CHECK((declaration_blob_id IS NULL AND declaration_site IS NULL AND declaration_rel_path IS NULL)
     OR (declaration_blob_id IS NOT NULL AND declaration_site IS NOT NULL AND declaration_rel_path IS NOT NULL)),
  PRIMARY KEY(topology_id, owner_module_path, side, spelling, impl_blob_id, impl_site, impl_rel_path, reason),
  FOREIGN KEY(topology_id) REFERENCES rust_crate_topologies(topology_id) ON DELETE CASCADE,
  FOREIGN KEY(impl_blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(declaration_blob_id) REFERENCES blobs(id)
) WITHOUT ROWID, STRICT;

CREATE INDEX rust_crate_unresolved_trait_impls_spelling
  ON rust_crate_unresolved_trait_impls(
    side, spelling, topology_id, impl_blob_id, impl_site, impl_rel_path, reason,
    impl_declaration_id
  );
CREATE INDEX rust_crate_unresolved_trait_impls_declaration
  ON rust_crate_unresolved_trait_impls(declaration_blob_id);
