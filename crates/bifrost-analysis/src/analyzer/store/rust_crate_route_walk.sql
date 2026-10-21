-- Import, rooted-reference and impl-prefix routes consume the same admitted
-- canonical relation. No row is admitted speculatively and no endpoint is
-- chosen by scan order. The output key includes the endpoint.
INSERT OR IGNORE INTO {output}
SELECT source.blob_id,source.{key},source.module_path,owner.crate_key,owner.module_path
FROM {sources} AS source
CROSS JOIN cr_binding_route_sources AS request
 ON request.segments_table='{segments}' AND request.blob_id=source.blob_id
 AND request.source_key=source.{key} AND request.module_path=source.module_path
CROSS JOIN cr_binding_imports AS input
 ON input.blob_id=request.blob_id AND input.import_ordinal=request.import_ordinal
 AND input.module_path=request.module_path
CROSS JOIN cr_binding_paths AS path
 ON path.blob_id=input.blob_id AND path.import_ordinal=input.import_ordinal
 AND path.module_path=input.module_path AND path.position=input.segments
CROSS JOIN cr_binding_owners AS owner ON owner.owner=path.owner
;
