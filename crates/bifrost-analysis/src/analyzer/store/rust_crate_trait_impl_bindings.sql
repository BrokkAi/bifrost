-- Where one half of an impl header resolves, by the routes a name in that
-- module already takes. A qualified path walks to the container its route
-- reaches and binds the type export named there. A bare name binds the impl
-- module's own named import, or the module's own declaration; the two cannot
-- both hold, because a module may not import and declare one name. A glob
-- import is weaker than either and is a separate statement that fills only
-- what these left unbound.
INSERT OR IGNORE INTO cr_impl_bindings
SELECT source.blob_id, source.relation_key, source.module_path, '{side}',
       exports.crate_key, exports.module_path, exports.name
FROM cr_impl_sources AS source
CROSS JOIN {routes} AS route ON route.blob_id=source.blob_id
  AND route.relation_key=source.relation_key AND route.module_path=source.module_path
CROSS JOIN cr_exports AS exports ON exports.crate_key=route.target_crate_key
  AND exports.module_path=route.target_module_path
  AND exports.namespace='type' AND exports.name=source.{name}
WHERE source.{segments} > 0
UNION ALL
SELECT source.blob_id, source.relation_key, source.module_path, '{side}',
       imports.target_crate_key, imports.target_module_path, imports.target_name
FROM cr_impl_sources AS source
CROSS JOIN cr_imports AS imports ON imports.module_path=source.module_path
  AND imports.namespace='type' AND imports.bound_name=source.{name}
WHERE source.{segments} = 0
UNION ALL
SELECT source.blob_id, source.relation_key, source.module_path, '{side}',
       exports.crate_key, exports.module_path, exports.name
FROM cr_impl_sources AS source
CROSS JOIN cr_exports AS exports
  ON exports.crate_key=(SELECT crate_key FROM cr_identity)
 AND exports.module_path=source.module_path
 AND exports.namespace='type' AND exports.name=source.{name}
WHERE source.{segments} = 0;
