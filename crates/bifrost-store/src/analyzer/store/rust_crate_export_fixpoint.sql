WITH candidates AS (
 SELECT destination.owner,target.namespace,source.bound_name AS name,
 target.target_crate_key,target.target_module_path,target.target_name,
 target.declaration_blob_id,target.declaration_site,'reexport' AS origin,
 source.visibility AS source_visibility,source.restricted_module_path AS source_restriction,
 target.visibility AS target_visibility,target.restricted_module_path AS target_restriction,
 target.owner AS exporting_owner
 FROM cr_binding_delta target
 CROSS JOIN cr_binding_lookups lookup INDEXED BY cr_binding_lookups_target
 ON lookup.owner=target.owner AND lookup.namespace=target.namespace AND lookup.name=target.name
 CROSS JOIN cr_binding_imports source ON source.blob_id=lookup.blob_id
 AND source.import_ordinal=lookup.import_ordinal AND source.module_path=lookup.module_path
 AND lookup.position=source.segments
 CROSS JOIN cr_binding_destinations destination ON destination.blob_id=source.blob_id
 AND destination.import_ordinal=source.import_ordinal AND destination.module_path=source.module_path
 WHERE source.is_glob=0 AND source.bound_name IS NOT NULL
 UNION ALL
 SELECT destination.owner,target.namespace,target.name,target.target_crate_key,target.target_module_path,target.target_name,
 target.declaration_blob_id,target.declaration_site,'glob_reexport',source.visibility,source.restricted_module_path,
 target.visibility,target.restricted_module_path,target.owner
 FROM cr_binding_delta target
 CROSS JOIN cr_binding_globs glob INDEXED BY cr_binding_globs_target ON glob.target_owner=target.owner
 LEFT JOIN cr_binding_masks mask ON mask.owner=glob.owner
 CROSS JOIN cr_binding_destinations destination INDEXED BY cr_binding_destinations_glob_owner
 ON destination.owner=glob.owner AND destination.is_glob=1
 CROSS JOIN cr_binding_imports source ON source.blob_id=destination.blob_id
 AND source.import_ordinal=destination.import_ordinal AND source.module_path=destination.module_path AND source.is_glob=1
 CROSS JOIN cr_binding_paths path ON path.blob_id=source.blob_id
 AND path.import_ordinal=source.import_ordinal AND path.module_path=source.module_path
 AND path.position=source.segments AND path.owner=target.owner
 WHERE source.is_glob=1 AND target.name<>'self' AND (mask.owner IS NULL OR mask.name=target.name)
 AND NOT EXISTS(SELECT 1 FROM cr_binding_imports named WHERE named.owner=source.owner
 AND named.is_glob=0 AND named.bound_name=target.name
 AND (mask.owner IS NULL OR named.blob_id<>mask.blob_id OR named.import_ordinal<>mask.import_ordinal OR named.module_path<>mask.module_path)
 AND (NOT EXISTS(SELECT 1 FROM cr_binding_import_complete done WHERE done.blob_id=named.blob_id
 AND done.import_ordinal=named.import_ordinal AND done.module_path=named.module_path AND done.namespace=target.namespace)
 OR EXISTS(SELECT 1 FROM cr_binding_import_present present WHERE present.blob_id=named.blob_id
 AND present.import_ordinal=named.import_ordinal AND present.module_path=named.module_path AND present.namespace=target.namespace)))
 UNION ALL
 SELECT destination.owner,'type',source.bound_name,target.target_crate_key,target.target_module_path,target.target_name,
 0,0,'reexport',source.visibility,source.restricted_module_path,'public',NULL,target.owner
 FROM cr_binding_prelude_reads target CROSS JOIN cr_binding_imports source
 ON source.blob_id=target.blob_id AND source.import_ordinal=target.import_ordinal
 AND source.module_path=target.module_path AND source.segments=target.position
 CROSS JOIN cr_binding_destinations destination ON destination.blob_id=source.blob_id
 AND destination.import_ordinal=source.import_ordinal AND destination.module_path=source.module_path
 WHERE target.origin='prelude' AND source.is_glob=0 AND source.bound_name IS NOT NULL
), domains AS (
 SELECT candidate.*,owner.module_path,owner.crate_key,exporting.crate_key AS exporting_crate,
 CASE source_visibility WHEN 'public' THEN NULL WHEN 'private' THEN owner.module_path
 WHEN 'crate' THEN 'crate' ELSE source_restriction END AS source_domain,
 CASE WHEN candidate.namespace='macro' AND target_visibility='private' AND source_visibility<>'public'
 AND owner.crate_key=exporting.crate_key THEN CASE source_visibility WHEN 'private' THEN owner.module_path
 WHEN 'crate' THEN 'crate' ELSE source_restriction END ELSE
 CASE target_visibility WHEN 'public' THEN NULL WHEN 'private' THEN exporting.module_path
 WHEN 'crate' THEN 'crate' ELSE target_restriction END END AS target_domain FROM candidates candidate CROSS JOIN cr_binding_owners owner ON owner.owner=candidate.owner
 CROSS JOIN cr_binding_owners exporting ON exporting.owner=candidate.exporting_owner
 WHERE (source_visibility<>'restricted' OR source_restriction IS NOT NULL)
 AND NOT EXISTS(SELECT 1 FROM cr_binding_targets item WHERE item.owner=candidate.owner
 AND item.namespace=candidate.namespace AND item.name=candidate.name AND item.origin='declaration'
 AND (item.target_crate_key<>candidate.target_crate_key OR item.target_module_path<>candidate.target_module_path
 OR item.target_name<>candidate.target_name))
), accessible AS (
 SELECT domains.*,CASE WHEN source_domain IS NULL THEN target_domain
 WHEN target_domain IS NULL THEN source_domain
 WHEN source_domain=target_domain OR substr(source_domain,1,length(target_domain)+2)=target_domain || '::'
 THEN source_domain WHEN substr(target_domain,1,length(source_domain)+2)=source_domain || '::'
 THEN target_domain END AS domain_path
 FROM domains WHERE target_visibility='public' OR (crate_key=exporting_crate AND target_domain IS NOT NULL
 AND (module_path=target_domain OR substr(module_path,1,length(target_domain)+2)=target_domain || '::'))
)
INSERT INTO cr_binding_targets
 SELECT owner,namespace,name,target_crate_key,target_module_path,target_name,
 declaration_blob_id,declaration_site,origin,
 CASE WHEN domain_path IS NULL THEN 'public'
 WHEN domain_path=module_path AND source_visibility='private' THEN 'private'
 WHEN domain_path='crate' THEN 'crate'
 WHEN domain_path=module_path THEN 'private' ELSE 'restricted' END,
 CASE WHEN domain_path<>'crate' AND domain_path<>module_path THEN domain_path END
 FROM accessible WHERE domain_path IS NOT NULL OR (source_domain IS NULL AND target_domain IS NULL)
 ON CONFLICT(owner,namespace,name,target_crate_key,target_module_path,target_name)
 DO UPDATE SET visibility=excluded.visibility,restricted_module_path=excluded.restricted_module_path
 WHERE (excluded.visibility='public' AND cr_binding_targets.visibility<>'public')
 OR (excluded.visibility='crate' AND cr_binding_targets.visibility IN ('private','restricted'))
 OR (excluded.visibility='restricted' AND (cr_binding_targets.visibility='private'
 OR (cr_binding_targets.visibility='restricted'
 AND length(excluded.restricted_module_path)<length(cr_binding_targets.restricted_module_path))));
