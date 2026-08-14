-- The `#[cfg(...)]` predicate on each persisted Rust import binding (ExecPlan
-- `.agents/plans/port-optimization-arc-to-upstream.md`, Phase 2 step 4).
--
-- Two `use` declarations of one name under `#[cfg(feature = "x")]` and
-- `#[cfg(not(feature = "x"))]` are ALTERNATIVES of a single binding, not two
-- competing ones. Without the predicate a reference under either arm resolves
-- ambiguously and reports no exact target, which is issue #1377. The resolver
-- therefore needs the predicate the `use` was written under, and that predicate
-- is a function of the file's bytes alone, so it belongs on the content-keyed
-- row rather than being recomputed by re-parsing every candidate importer.
--
-- Only the two shapes a disjointness proof can use are stored -- a bare atom
-- and its negation -- with everything richer reduced to 'unknown', which proves
-- nothing. The encoding is
-- `brokk_bifrost_core::analyzer::rust_facts::encode_rust_cfg_condition`:
-- 'always', 'unknown', 'atom <predicate>', 'not <predicate>'.
--
-- 'always' is the default because an unguarded `use` is the overwhelming
-- majority and is exactly what a row written before this column meant.
ALTER TABLE rust_import_targets
  ADD COLUMN cfg_condition TEXT NOT NULL DEFAULT 'always';

-- Whether the binding came from `extern crate name as alias;` rather than from
-- a `use`.
--
-- `extern crate dep as tk;` binds the CRATE under `tk` and nothing else, where
-- `use dep as tk;` additionally binds whatever `dep` names in the current
-- module. Every other stored column is identical between the two, so a reader
-- that cannot tell them apart resolves `tk::Item` to a same-named local `mod
-- dep` as well as to the dependency. 0 is the default because a `use` is the
-- overwhelming majority and is what a row written before this column meant.
ALTER TABLE rust_import_targets
  ADD COLUMN is_extern_crate INTEGER NOT NULL DEFAULT 0;
