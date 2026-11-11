-- #11173: route_questions::route_sql (CrateNameUnits) will seek crate_name
-- and target_kind, then join live summaries by summary_id.
CREATE INDEX rust_resolution_unit_summary_contexts_name_kind
  ON rust_resolution_unit_summary_contexts(crate_name, target_kind, summary_id);

-- #11173: rust_crate_context::IMPORT_MODULE_PREFIX_STARTS and
-- MACRO_GATED_IMPORT_ROUTE (also used by rust_demand::rows) will seek
-- summary_id, module_path, member_ordinal, binder_scope, namespace.
-- Their direct arms additionally bind bound_name; overlay arms bind the
-- selected source import's bound_name instead, so namespace must precede it.
CREATE INDEX rust_resolution_unit_summary_import_routes_module_scope
  ON rust_resolution_unit_summary_import_routes(
    summary_id, module_path, member_ordinal, binder_scope, namespace, bound_name);
