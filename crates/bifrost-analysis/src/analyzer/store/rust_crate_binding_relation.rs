//! One crate's monotone import binding relation. Endpoints are admitted before
//! inventories close; closure is needed only to conclude that a name is absent.
use super::*;
use crate::analyzer::semantic::CancellationToken;
use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmRequest, DenseUsizeGraph, strongly_connected_components,
};

pub(super) const SCHEMA_SQL: &str = "
CREATE TEMP TABLE IF NOT EXISTS cr_binding_owners(
 owner INTEGER PRIMARY KEY, crate_key BLOB NOT NULL, module_path TEXT NOT NULL,
 blob_id INTEGER NOT NULL, binder_scope INTEGER NOT NULL,
 parent_owner INTEGER, open INTEGER NOT NULL DEFAULT 0,
 UNIQUE(crate_key,module_path,blob_id,binder_scope));
CREATE TEMP TABLE IF NOT EXISTS cr_binding_imports(
 blob_id INTEGER NOT NULL, import_ordinal INTEGER NOT NULL, module_path TEXT NOT NULL,
 owner INTEGER NOT NULL, is_glob INTEGER NOT NULL, bound_name TEXT, imported_name TEXT,
 visibility TEXT NOT NULL, restricted_module_path TEXT, segments INTEGER NOT NULL,
 PRIMARY KEY(blob_id,import_ordinal,module_path)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS cr_binding_imports_owner
 ON cr_binding_imports(owner,bound_name,is_glob);
-- Absolute requests read the extern prelude in its own lookup context, so
-- module declarations cannot shadow it (Rust 2018 and later).
CREATE TEMP TABLE IF NOT EXISTS cr_binding_absolute_sources(
 blob_id INTEGER NOT NULL,import_ordinal INTEGER NOT NULL,module_path TEXT NOT NULL,
 PRIMARY KEY(blob_id,import_ordinal,module_path)) WITHOUT ROWID;
CREATE TEMP TABLE IF NOT EXISTS cr_binding_names(
 owner INTEGER NOT NULL, namespace TEXT NOT NULL, name TEXT NOT NULL,
 PRIMARY KEY(owner,namespace,name)) WITHOUT ROWID;
CREATE TEMP TABLE IF NOT EXISTS cr_binding_targets(
 owner INTEGER NOT NULL, namespace TEXT NOT NULL, name TEXT NOT NULL,
 target_crate_key BLOB NOT NULL, target_module_path TEXT NOT NULL, target_name TEXT NOT NULL,
 declaration_blob_id INTEGER NOT NULL, declaration_site INTEGER NOT NULL,
 origin TEXT NOT NULL, visibility TEXT NOT NULL, restricted_module_path TEXT,
 PRIMARY KEY(owner,namespace,name,target_crate_key,target_module_path,target_name)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS cr_binding_targets_name ON cr_binding_targets(owner,name,namespace);
-- Uncertain endpoints remain in the canonical relation and in published
-- evidence. They are never projected as exact exports or import bindings.
CREATE TEMP TABLE IF NOT EXISTS cr_binding_uncertain(
 node INTEGER NOT NULL,target_crate_key BLOB NOT NULL,target_module_path TEXT NOT NULL,target_name TEXT NOT NULL,
 PRIMARY KEY(node,target_crate_key,target_module_path,target_name)) WITHOUT ROWID;
CREATE TEMP TABLE IF NOT EXISTS cr_binding_certain(
 node INTEGER NOT NULL,target_crate_key BLOB NOT NULL,target_module_path TEXT NOT NULL,target_name TEXT NOT NULL,
 PRIMARY KEY(node,target_crate_key,target_module_path,target_name)) WITHOUT ROWID;
CREATE TEMP VIEW IF NOT EXISTS cr_binding_exact_targets AS
 SELECT target.* FROM cr_binding_targets target CROSS JOIN cr_binding_nodes node
 ON node.owner=target.owner AND node.namespace=target.namespace AND node.name=target.name
 CROSS JOIN cr_binding_certain proof ON proof.node=node.node
 AND proof.target_crate_key=target.target_crate_key
 AND proof.target_module_path=target.target_module_path AND proof.target_name=target.target_name;

CREATE TEMP TABLE IF NOT EXISTS cr_binding_delta AS SELECT * FROM cr_binding_targets WHERE 0;
CREATE UNIQUE INDEX IF NOT EXISTS cr_binding_delta_key ON cr_binding_delta(owner,namespace,name,target_crate_key,target_module_path,target_name);
CREATE TEMP TABLE IF NOT EXISTS cr_binding_delta_next AS SELECT * FROM cr_binding_targets WHERE 0;
CREATE UNIQUE INDEX IF NOT EXISTS cr_binding_delta_next_key ON cr_binding_delta_next(owner,namespace,name,target_crate_key,target_module_path,target_name);
CREATE TEMP TRIGGER IF NOT EXISTS cr_binding_delta_insert AFTER INSERT ON cr_binding_targets BEGIN
 INSERT INTO cr_binding_delta_next VALUES(NEW.owner,NEW.namespace,NEW.name,
 NEW.target_crate_key,NEW.target_module_path,NEW.target_name,NEW.declaration_blob_id,NEW.declaration_site,
 NEW.origin,NEW.visibility,NEW.restricted_module_path) ON CONFLICT(owner,namespace,name,target_crate_key,target_module_path,target_name)
 DO UPDATE SET declaration_blob_id=excluded.declaration_blob_id,declaration_site=excluded.declaration_site,
 origin=excluded.origin,visibility=excluded.visibility,restricted_module_path=excluded.restricted_module_path;
END;
CREATE TEMP TRIGGER IF NOT EXISTS cr_binding_delta_update AFTER UPDATE ON cr_binding_targets BEGIN
 INSERT INTO cr_binding_delta_next VALUES(NEW.owner,NEW.namespace,NEW.name,
 NEW.target_crate_key,NEW.target_module_path,NEW.target_name,NEW.declaration_blob_id,NEW.declaration_site,
 NEW.origin,NEW.visibility,NEW.restricted_module_path) ON CONFLICT(owner,namespace,name,target_crate_key,target_module_path,target_name)
 DO UPDATE SET declaration_blob_id=excluded.declaration_blob_id,declaration_site=excluded.declaration_site,
 origin=excluded.origin,visibility=excluded.visibility,restricted_module_path=excluded.restricted_module_path;
END;
CREATE TEMP TABLE IF NOT EXISTS cr_binding_complete(
 owner INTEGER NOT NULL, namespace TEXT NOT NULL, name TEXT NOT NULL,
 PRIMARY KEY(owner,namespace,name)) WITHOUT ROWID;
CREATE TEMP TABLE IF NOT EXISTS cr_binding_paths(
 blob_id INTEGER NOT NULL, import_ordinal INTEGER NOT NULL, module_path TEXT NOT NULL,
 position INTEGER NOT NULL, owner INTEGER NOT NULL,
 PRIMARY KEY(blob_id,import_ordinal,module_path,position,owner)) WITHOUT ROWID;
CREATE TEMP TABLE IF NOT EXISTS cr_binding_path_complete(
 blob_id INTEGER NOT NULL, import_ordinal INTEGER NOT NULL, module_path TEXT NOT NULL,
 position INTEGER NOT NULL,
 PRIMARY KEY(blob_id,import_ordinal,module_path,position)) WITHOUT ROWID;
CREATE TEMP TABLE IF NOT EXISTS cr_binding_segments(
 blob_id INTEGER NOT NULL,import_ordinal INTEGER NOT NULL,ordinal INTEGER NOT NULL,segment TEXT NOT NULL,
 PRIMARY KEY(blob_id,import_ordinal,ordinal)) WITHOUT ROWID;
CREATE TEMP TABLE IF NOT EXISTS cr_binding_route_sources(
 segments_table TEXT NOT NULL,blob_id INTEGER NOT NULL,source_key INTEGER NOT NULL,module_path TEXT NOT NULL,
 import_ordinal INTEGER NOT NULL,
 PRIMARY KEY(segments_table,blob_id,source_key,module_path)) WITHOUT ROWID;
CREATE TEMP TABLE IF NOT EXISTS cr_binding_import_present(
 blob_id INTEGER NOT NULL,import_ordinal INTEGER NOT NULL,module_path TEXT NOT NULL,namespace TEXT NOT NULL,
 PRIMARY KEY(blob_id,import_ordinal,module_path,namespace)) WITHOUT ROWID;
CREATE TEMP TABLE IF NOT EXISTS cr_binding_open_sources(
 blob_id INTEGER NOT NULL,import_ordinal INTEGER NOT NULL,module_path TEXT NOT NULL,
 namespace TEXT NOT NULL,PRIMARY KEY(blob_id,import_ordinal,module_path,namespace)) WITHOUT ROWID;
CREATE TEMP TABLE IF NOT EXISTS cr_binding_import_complete(
 blob_id INTEGER NOT NULL, import_ordinal INTEGER NOT NULL, module_path TEXT NOT NULL,
 namespace TEXT NOT NULL,
 PRIMARY KEY(blob_id,import_ordinal,module_path,namespace)) WITHOUT ROWID;
CREATE TEMP TABLE IF NOT EXISTS cr_binding_open_names(
 owner INTEGER NOT NULL,namespace TEXT NOT NULL,name TEXT NOT NULL,
 reason TEXT NOT NULL DEFAULT 'OpenBoundary',boundary TEXT NOT NULL DEFAULT 'workspace_local',
 inventory TEXT NOT NULL DEFAULT 'null' CHECK(json_valid(inventory)),
 PRIMARY KEY(owner,namespace,name,reason,boundary,inventory)) WITHOUT ROWID;
CREATE TEMP TABLE IF NOT EXISTS cr_binding_fallback(
 owner INTEGER NOT NULL, namespace TEXT NOT NULL, name TEXT NOT NULL,
 PRIMARY KEY(owner,namespace,name)) WITHOUT ROWID;
CREATE TEMP TABLE IF NOT EXISTS cr_binding_globs(
 owner INTEGER NOT NULL, target_owner INTEGER NOT NULL,
 PRIMARY KEY(owner,target_owner)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS cr_binding_globs_target ON cr_binding_globs(target_owner,owner);
CREATE TEMP TABLE IF NOT EXISTS cr_binding_masks(
 owner INTEGER PRIMARY KEY,base_owner INTEGER NOT NULL,blob_id INTEGER NOT NULL,
 import_ordinal INTEGER NOT NULL,module_path TEXT NOT NULL,name TEXT NOT NULL,
 UNIQUE(blob_id,import_ordinal,module_path));
CREATE TEMP TABLE IF NOT EXISTS cr_binding_destinations(
 blob_id INTEGER NOT NULL,import_ordinal INTEGER NOT NULL,module_path TEXT NOT NULL,
 owner INTEGER NOT NULL,PRIMARY KEY(blob_id,import_ordinal,module_path,owner)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS cr_binding_destinations_owner ON cr_binding_destinations(owner,blob_id,import_ordinal,module_path);
CREATE TEMP TABLE IF NOT EXISTS cr_binding_lookups(
 blob_id INTEGER NOT NULL,import_ordinal INTEGER NOT NULL,module_path TEXT NOT NULL,
 position INTEGER NOT NULL,owner INTEGER NOT NULL,namespace TEXT NOT NULL,name TEXT NOT NULL,
 PRIMARY KEY(blob_id,import_ordinal,module_path,position,owner,namespace,name)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS cr_binding_lookups_target ON cr_binding_lookups(owner,namespace,name);
CREATE TEMP TABLE IF NOT EXISTS cr_binding_nodes(
 node INTEGER PRIMARY KEY,owner INTEGER NOT NULL,namespace TEXT NOT NULL,name TEXT NOT NULL,
 UNIQUE(owner,namespace,name));
CREATE TEMP TABLE IF NOT EXISTS cr_binding_edges(
 source INTEGER NOT NULL,target INTEGER NOT NULL,negative INTEGER NOT NULL,propagates_ambiguity INTEGER NOT NULL,
 PRIMARY KEY(source,target,negative)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS cr_binding_edges_target ON cr_binding_edges(target,source,negative,propagates_ambiguity);
CREATE TEMP TABLE IF NOT EXISTS cr_binding_components(
 node INTEGER PRIMARY KEY, component INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS cr_binding_components_component
 ON cr_binding_components(component,node);
CREATE INDEX IF NOT EXISTS cr_binding_paths_target ON cr_binding_paths(owner,blob_id,import_ordinal,module_path,position);
CREATE INDEX IF NOT EXISTS cr_binding_imports_terminal ON cr_binding_imports(segments,imported_name,is_glob);
CREATE TEMP TRIGGER IF NOT EXISTS cr_binding_new_path AFTER INSERT ON cr_binding_paths BEGIN
 INSERT INTO cr_binding_delta_next
 SELECT target.* FROM cr_binding_imports source
 CROSS JOIN cr_binding_targets target ON target.owner=NEW.owner
 WHERE source.blob_id=NEW.blob_id AND source.import_ordinal=NEW.import_ordinal
 AND source.module_path=NEW.module_path AND source.segments=NEW.position
 AND (source.is_glob=1 OR source.imported_name=target.name) ON CONFLICT(owner,namespace,name,target_crate_key,target_module_path,target_name)
 DO UPDATE SET declaration_blob_id=excluded.declaration_blob_id,declaration_site=excluded.declaration_site,
 origin=excluded.origin,visibility=excluded.visibility,restricted_module_path=excluded.restricted_module_path;
END;
CREATE TEMP TRIGGER IF NOT EXISTS cr_binding_named_determined AFTER INSERT ON cr_binding_import_complete BEGIN
 INSERT INTO cr_binding_delta_next
 SELECT target.* FROM cr_binding_imports source
 CROSS JOIN cr_binding_globs glob ON glob.owner=source.owner
 CROSS JOIN cr_binding_targets target ON target.owner=glob.target_owner
 AND target.namespace=NEW.namespace AND target.name=source.bound_name
 WHERE source.blob_id=NEW.blob_id AND source.import_ordinal=NEW.import_ordinal
 AND source.module_path=NEW.module_path AND source.is_glob=0 ON CONFLICT(owner,namespace,name,target_crate_key,target_module_path,target_name)
 DO UPDATE SET declaration_blob_id=excluded.declaration_blob_id,declaration_site=excluded.declaration_site,
 origin=excluded.origin,visibility=excluded.visibility,restricted_module_path=excluded.restricted_module_path;
END;

CREATE TEMP TRIGGER IF NOT EXISTS cr_binding_new_lookup AFTER INSERT ON cr_binding_lookups BEGIN
 INSERT INTO cr_binding_delta_next SELECT target.* FROM cr_binding_targets target
 WHERE target.owner=NEW.owner AND target.namespace=NEW.namespace AND target.name=NEW.name ON CONFLICT(owner,namespace,name,target_crate_key,target_module_path,target_name)
 DO UPDATE SET declaration_blob_id=excluded.declaration_blob_id,declaration_site=excluded.declaration_site,
 origin=excluded.origin,visibility=excluded.visibility,restricted_module_path=excluded.restricted_module_path;
END;
CREATE TEMP TABLE IF NOT EXISTS cr_binding_path_delta AS SELECT * FROM cr_binding_paths WHERE 0;
CREATE TEMP TABLE IF NOT EXISTS cr_binding_path_next AS SELECT * FROM cr_binding_paths WHERE 0;
CREATE TEMP TABLE IF NOT EXISTS cr_binding_name_delta AS SELECT * FROM cr_binding_names WHERE 0;
CREATE TEMP TABLE IF NOT EXISTS cr_binding_name_next AS SELECT * FROM cr_binding_names WHERE 0;
CREATE TEMP TABLE IF NOT EXISTS cr_binding_lookup_new AS SELECT * FROM cr_binding_lookups WHERE 0;
CREATE INDEX IF NOT EXISTS cr_binding_name_delta_owner ON cr_binding_name_delta(owner,namespace,name);
CREATE TEMP TRIGGER IF NOT EXISTS cr_binding_path_queued AFTER INSERT ON cr_binding_paths BEGIN
 INSERT INTO cr_binding_path_next VALUES(NEW.blob_id,NEW.import_ordinal,NEW.module_path,NEW.position,NEW.owner);
END;
CREATE TEMP TRIGGER IF NOT EXISTS cr_binding_name_queued AFTER INSERT ON cr_binding_names BEGIN
 INSERT INTO cr_binding_name_next VALUES(NEW.owner,NEW.namespace,NEW.name);
END;
CREATE TEMP TRIGGER IF NOT EXISTS cr_binding_lookup_queued AFTER INSERT ON cr_binding_lookups BEGIN
 INSERT INTO cr_binding_lookup_new VALUES(NEW.blob_id,NEW.import_ordinal,NEW.module_path,NEW.position,NEW.owner,NEW.namespace,NEW.name);
END;
CREATE TEMP TRIGGER IF NOT EXISTS cr_binding_glob_names AFTER INSERT ON cr_binding_globs BEGIN
 INSERT OR IGNORE INTO cr_binding_names SELECT NEW.target_owner,namespace,name FROM cr_binding_names WHERE owner=NEW.owner;
 INSERT OR IGNORE INTO cr_binding_names SELECT NEW.owner,namespace,name FROM cr_binding_targets target WHERE owner=NEW.target_owner
 AND NOT EXISTS(SELECT 1 FROM cr_binding_masks mask WHERE mask.owner=NEW.owner AND mask.name<>target.name);
END;
CREATE INDEX IF NOT EXISTS cr_binding_lookups_name ON cr_binding_lookups(name,namespace,position);
CREATE TEMP VIEW IF NOT EXISTS cr_binding_prelude_reads(blob_id,import_ordinal,module_path,position,owner,namespace,name,target_crate_key,target_module_path,target_name,declaration_blob_id,declaration_site,origin,visibility,restricted_module_path) AS
 SELECT lookup.blob_id,lookup.import_ordinal,lookup.module_path,lookup.position,
 lookup.owner,'type',lookup.name,dependency.dependency_crate_key,'crate','self',0,0,'prelude','public',NULL
 FROM cr_dependencies dependency CROSS JOIN cr_binding_lookups lookup INDEXED BY cr_binding_lookups_name
 ON lookup.name=dependency.extern_name AND dependency.dependency_crate_key IS NOT NULL
 LEFT JOIN cr_binding_masks mask ON mask.owner=lookup.owner
 CROSS JOIN cr_binding_owners context ON context.owner=lookup.owner
 WHERE lookup.position=0 AND lookup.namespace='type'
 AND (context.parent_owner IS NULL OR (EXISTS(SELECT 1 FROM cr_binding_complete parent
 WHERE parent.owner=context.parent_owner AND parent.namespace='type' AND parent.name=lookup.name)
 AND NOT EXISTS(SELECT 1 FROM cr_binding_targets parent WHERE parent.owner=context.parent_owner
 AND parent.namespace='type' AND parent.name=lookup.name AND parent.origin IN ('declaration','reexport'))))
 AND NOT EXISTS(SELECT 1 FROM cr_binding_targets strong WHERE strong.owner=lookup.owner
 AND strong.namespace='type' AND strong.name=lookup.name AND strong.origin IN ('declaration','reexport'))
 AND NOT EXISTS(SELECT 1 FROM cr_binding_imports blocker
 WHERE blocker.owner=COALESCE(mask.base_owner,lookup.owner) AND blocker.bound_name=lookup.name AND blocker.is_glob=0
 AND (mask.owner IS NULL OR blocker.blob_id<>mask.blob_id OR blocker.import_ordinal<>mask.import_ordinal OR blocker.module_path<>mask.module_path)
 AND (NOT EXISTS(SELECT 1 FROM cr_binding_import_complete done WHERE done.blob_id=blocker.blob_id
 AND done.import_ordinal=blocker.import_ordinal AND done.module_path=blocker.module_path AND done.namespace='type')
 OR EXISTS(SELECT 1 FROM cr_binding_import_present present WHERE present.blob_id=blocker.blob_id
 AND present.import_ordinal=blocker.import_ordinal AND present.module_path=blocker.module_path AND present.namespace='type')));
CREATE TEMP VIEW IF NOT EXISTS cr_binding_delta_reads AS
 SELECT lookup.blob_id,lookup.import_ordinal,lookup.module_path,lookup.position,target.*
 FROM cr_binding_delta target CROSS JOIN cr_binding_lookups lookup INDEXED BY cr_binding_lookups_target
 ON target.owner=lookup.owner AND target.namespace=lookup.namespace AND target.name=lookup.name
 UNION ALL SELECT * FROM cr_binding_prelude_reads;
CREATE TEMP VIEW IF NOT EXISTS cr_binding_reads AS
 SELECT lookup.blob_id,lookup.import_ordinal,lookup.module_path,lookup.position,target.*
 FROM cr_binding_lookups lookup CROSS JOIN cr_binding_targets target
 ON target.owner=lookup.owner AND target.namespace=lookup.namespace AND target.name=lookup.name
 UNION ALL SELECT * FROM cr_binding_prelude_reads;

-- A completeness dependency need not carry a binding: a source can contain
-- only private names. Ambiguity follows the accessible admitted endpoints.
CREATE TEMP VIEW IF NOT EXISTS cr_binding_carries AS
 WITH accessible AS (
 SELECT glob.owner,glob.target_owner,provided.namespace,provided.name,provided.target_crate_key,
 provided.target_module_path,provided.target_name,provided.visibility,provided.restricted_module_path,
 consumer.crate_key AS consumer_crate,consumer.module_path AS consumer_module,
 provider.crate_key AS provider_crate,
 CASE provided.visibility WHEN 'public' THEN NULL WHEN 'private' THEN provider.module_path
 WHEN 'crate' THEN 'crate' ELSE provided.restricted_module_path END AS domain
 FROM cr_binding_globs glob
 CROSS JOIN cr_binding_owners consumer ON consumer.owner=glob.owner
 CROSS JOIN cr_binding_owners provider ON provider.owner=glob.target_owner
 CROSS JOIN cr_binding_targets provided ON provided.owner=glob.target_owner
 )
 SELECT accessible.owner,accessible.target_owner,accessible.namespace,accessible.name
 FROM accessible CROSS JOIN cr_binding_targets admitted
 ON admitted.owner=accessible.owner AND admitted.namespace=accessible.namespace AND admitted.name=accessible.name
 AND admitted.target_crate_key=accessible.target_crate_key
 AND admitted.target_module_path=accessible.target_module_path AND admitted.target_name=accessible.target_name
 WHERE accessible.visibility='public' OR (accessible.consumer_crate=accessible.provider_crate
 AND accessible.domain IS NOT NULL AND (accessible.consumer_module=accessible.domain
 OR substr(accessible.consumer_module,1,length(accessible.domain)+2)=accessible.domain || '::'));
CREATE TEMP VIEW IF NOT EXISTS cr_binding_visibility_reads AS
 WITH reads(consumer,provider,namespace,name) AS (
 SELECT glob.owner,glob.target_owner,target.namespace,target.name
 FROM cr_binding_globs glob CROSS JOIN cr_binding_targets target ON target.owner=glob.target_owner
 WHERE NOT EXISTS(SELECT 1 FROM cr_binding_targets strong WHERE strong.owner=glob.owner
 AND strong.namespace=target.namespace AND strong.name=target.name AND strong.origin IN ('declaration','reexport'))
 UNION
 SELECT source.owner,lookup.owner,lookup.namespace,lookup.name
 FROM cr_binding_lookups lookup CROSS JOIN cr_binding_imports source
 ON source.blob_id=lookup.blob_id AND source.import_ordinal=lookup.import_ordinal AND source.module_path=lookup.module_path
 )
 SELECT reads.*,target.target_crate_key,target.target_module_path,target.target_name,target.origin,
 target.visibility,target.restricted_module_path,
 CASE WHEN target.visibility='public' OR (consumer.crate_key=provider.crate_key AND
 (consumer.module_path=CASE target.visibility WHEN 'private' THEN provider.module_path
 WHEN 'crate' THEN 'crate' ELSE target.restricted_module_path END
 OR substr(consumer.module_path,1,length(CASE target.visibility WHEN 'private' THEN provider.module_path
 WHEN 'crate' THEN 'crate' ELSE target.restricted_module_path END)+2)=
 CASE target.visibility WHEN 'private' THEN provider.module_path WHEN 'crate' THEN 'crate'
 ELSE target.restricted_module_path END || '::')) THEN 1 ELSE 0 END AS accessible
 FROM reads CROSS JOIN cr_binding_targets target ON target.owner=reads.provider
 AND target.namespace=reads.namespace AND target.name=reads.name
 CROSS JOIN cr_binding_owners consumer ON consumer.owner=reads.consumer
 CROSS JOIN cr_binding_owners provider ON provider.owner=reads.provider;

";

pub(super) const CLEAR_SQL: &str = "
DELETE FROM cr_binding_absolute_sources; DELETE FROM cr_binding_certain; DELETE FROM cr_binding_uncertain; DELETE FROM cr_binding_masks; DELETE FROM cr_binding_destinations; DELETE FROM cr_binding_lookups; DELETE FROM cr_binding_nodes; DELETE FROM cr_binding_edges; DELETE FROM cr_binding_delta; DELETE FROM cr_binding_delta_next; DELETE FROM cr_binding_segments; DELETE FROM cr_binding_route_sources; DELETE FROM cr_binding_targets; DELETE FROM cr_binding_names;
DELETE FROM cr_binding_complete; DELETE FROM cr_binding_paths;
DELETE FROM cr_binding_path_complete; DELETE FROM cr_binding_import_complete;
DELETE FROM cr_binding_open_names; DELETE FROM cr_binding_fallback; DELETE FROM cr_binding_globs; DELETE FROM cr_binding_components;
DELETE FROM cr_binding_open_sources; DELETE FROM cr_binding_import_present; DELETE FROM cr_binding_imports; DELETE FROM cr_binding_owners;DELETE FROM cr_binding_path_delta;
DELETE FROM cr_binding_path_next;
DELETE FROM cr_binding_name_delta;
DELETE FROM cr_binding_name_next;
DELETE FROM cr_binding_lookup_new;
";

pub(super) const OWNERS_SQL: &str = "INSERT OR IGNORE INTO cr_binding_owners(
 crate_key,module_path,blob_id,binder_scope)
 SELECT crate_key,container_path,0,0 FROM cr_containers_all
 UNION SELECT crate_key,'crate',0,-1 FROM cr_identity
 UNION SELECT identity.crate_key,source.module_path,source.blob_id,source.binder_scope
 FROM cr_identity identity CROSS JOIN cr_source_imports source
 WHERE NOT EXISTS(SELECT 1 FROM cr_module_imports module
 WHERE module.blob_id=source.blob_id AND module.import_ordinal=source.import_ordinal
 AND module.module_path=source.module_path)";

pub(super) const PARENTS_SQL: &str = "UPDATE cr_binding_owners AS owner SET parent_owner=(
 SELECT parent.owner FROM cr_binding_owners parent
 WHERE parent.crate_key=owner.crate_key AND parent.module_path=owner.module_path
 AND parent.blob_id=0 AND parent.binder_scope=0)
 WHERE owner.blob_id<>0";

// Import contexts carry lexical extents as well as native scope identities.
// Select an enclosing local owner, if any, instead of merging equal aliases in
// separate functions into a module-wide binding.
pub(super) const LEXICAL_PARENTS_SQL: &str =
    "UPDATE cr_binding_owners AS owner SET parent_owner=COALESCE((
 SELECT enclosing.owner FROM cr_binding_owners enclosing
 CROSS JOIN cr_source_imports inner_import
 ON inner_import.blob_id=owner.blob_id AND inner_import.binder_scope=owner.binder_scope
 AND inner_import.module_path=owner.module_path
 CROSS JOIN source_rust_import_targets inner_source
 ON inner_source.blob_id=inner_import.blob_id AND inner_source.ordinal=inner_import.import_ordinal
 CROSS JOIN cr_source_imports outer_import
 ON outer_import.blob_id=enclosing.blob_id AND outer_import.binder_scope=enclosing.binder_scope
 AND outer_import.module_path=enclosing.module_path
 CROSS JOIN source_rust_import_targets outer_source
 ON outer_source.blob_id=outer_import.blob_id AND outer_source.ordinal=outer_import.import_ordinal
 WHERE enclosing.crate_key=owner.crate_key AND enclosing.module_path=owner.module_path
 AND enclosing.blob_id=owner.blob_id AND enclosing.owner<>owner.owner
 AND outer_source.local_start<=inner_source.local_start
 AND outer_source.local_end>=inner_source.local_end
 AND outer_source.local_end-outer_source.local_start>inner_source.local_end-inner_source.local_start
 ORDER BY outer_source.local_end-outer_source.local_start LIMIT 1),parent_owner)
 WHERE owner.blob_id<>0";

pub(super) const IMPORTS_SQL: &str = "INSERT INTO cr_binding_imports
 SELECT source.blob_id,source.import_ordinal,source.module_path,owner.owner,
 source.is_glob,source.bound_name,source.imported_name,cr_visibility(source.visibility),
 restriction.restricted_module_path,
 (SELECT COUNT(*) FROM source_rust_import_module_segments segment
 WHERE segment.blob_id=source.blob_id AND segment.import_ordinal=source.import_ordinal)
 FROM cr_source_imports source
 CROSS JOIN cr_identity identity
 CROSS JOIN cr_binding_owners owner ON owner.crate_key=identity.crate_key
 AND owner.module_path=source.module_path
 AND ((owner.blob_id=source.blob_id AND owner.binder_scope=source.binder_scope)
 OR (owner.blob_id=0 AND owner.binder_scope=0 AND EXISTS(
 SELECT 1 FROM cr_module_imports module WHERE module.blob_id=source.blob_id
 AND module.import_ordinal=source.import_ordinal AND module.module_path=source.module_path)))
 LEFT JOIN cr_restrictions restriction ON restriction.module_path=source.module_path
 AND restriction.visibility=source.visibility";

pub(super) const SEED_SQL: &str = "INSERT OR IGNORE INTO cr_binding_targets
 SELECT owner.owner,exports.namespace,exports.name,exports.crate_key,exports.module_path,exports.name,
 exports.declaration_blob_id,exports.declaration_site,'declaration',exports.visibility,exports.restricted_module_path
 FROM cr_exports exports CROSS JOIN cr_binding_owners owner
 ON owner.crate_key=exports.crate_key AND owner.module_path=exports.module_path
 AND owner.blob_id=0 AND owner.binder_scope=0 WHERE exports.origin='declaration'";

// The root anchor is already lowered into the path's first local identity.
// Read it by the source path/catalog keys; no syntax or lowered fact changes.
pub(super) const ABSOLUTE_SOURCES_SQL: &str = "INSERT OR IGNORE INTO cr_binding_absolute_sources
 SELECT source.blob_id,source.import_ordinal,source.module_path
 FROM cr_source_imports source CROSS JOIN source_rust_import_targets syntax
 ON syntax.blob_id=source.blob_id AND syntax.ordinal=source.import_ordinal
 WHERE syntax.leading_absolute=1
 UNION ALL SELECT source.blob_id,-1-4*source.route_key,source.module_path
 FROM cr_root_sources source CROSS JOIN resolution_paths path
 ON path.blob_id=source.blob_id AND path.path=source.route_key
 CROSS JOIN resolution_semantic_catalog anchor ON anchor.blob_id=path.blob_id
 AND anchor.local_key=json_extract(path.end_fixed_key,'$[0][0]')
 WHERE anchor.identity_digest=?1
 UNION ALL SELECT source.blob_id,-2-4*source.relation_key,source.module_path
 FROM cr_impl_sources source CROSS JOIN source_rust_impl_items item
 ON item.blob_id=source.blob_id AND item.declaration_id=source.impl_declaration_id
 CROSS JOIN source_rust_types target ON target.blob_id=item.blob_id
 AND target.occurrence_id=item.target_type_occurrence_id AND target.leading_absolute=1
 UNION ALL SELECT source.blob_id,-3-4*source.relation_key,source.module_path
 FROM cr_impl_sources source CROSS JOIN source_rust_impl_items item
 ON item.blob_id=source.blob_id AND item.declaration_id=source.impl_declaration_id
 CROSS JOIN source_rust_types target ON target.blob_id=item.blob_id
 AND target.occurrence_id=item.trait_type_occurrence_id AND target.leading_absolute=1";

pub(super) const SEED_PATHS_SQL: &str = "INSERT OR IGNORE INTO cr_binding_paths
 SELECT source.blob_id,source.import_ordinal,source.module_path,0,
 CASE WHEN ?1<>'2015' AND EXISTS(SELECT 1 FROM cr_binding_absolute_sources absolute
 WHERE absolute.blob_id=source.blob_id AND absolute.import_ordinal=source.import_ordinal
 AND absolute.module_path=source.module_path) THEN extern_prelude.owner
 WHEN ?1='2015' AND (source.import_ordinal>=0 OR EXISTS(SELECT 1 FROM cr_binding_absolute_sources absolute
 WHERE absolute.blob_id=source.blob_id AND absolute.import_ordinal=source.import_ordinal
 AND absolute.module_path=source.module_path)) AND NOT EXISTS(SELECT 1 FROM cr_binding_segments first
 WHERE first.blob_id=source.blob_id AND first.import_ordinal=source.import_ordinal
 AND first.ordinal=0 AND first.segment IN ('crate','self','super'))
 THEN root.owner ELSE source.owner END
 FROM cr_binding_imports source CROSS JOIN cr_identity identity
 CROSS JOIN cr_binding_owners root ON root.crate_key=identity.crate_key
 AND root.module_path='crate' AND root.blob_id=0 AND root.binder_scope=0
 CROSS JOIN cr_binding_owners extern_prelude ON extern_prelude.crate_key=identity.crate_key
 AND extern_prelude.module_path='crate' AND extern_prelude.blob_id=0 AND extern_prelude.binder_scope=-1";

pub(super) const SEED_PATH_COMPLETE_SQL: &str = "INSERT OR IGNORE INTO cr_binding_path_complete
 SELECT blob_id,import_ordinal,module_path,0 FROM cr_binding_imports";

pub(super) const SEED_DEMANDS_SQL: &str = "INSERT OR IGNORE INTO cr_binding_names
 SELECT source.owner,namespace.value,source.bound_name FROM cr_binding_imports source
 CROSS JOIN json_each('[\"type\",\"value\",\"macro\"]') namespace
 WHERE source.is_glob=0 AND source.bound_name IS NOT NULL
 UNION SELECT mask.owner,namespace.value,mask.name FROM cr_binding_masks mask
 CROSS JOIN json_each('[\"type\",\"value\",\"macro\"]') namespace";

pub(super) const DEMANDS_SQL: &str = "INSERT OR IGNORE INTO cr_binding_names
 SELECT owner,namespace,name FROM cr_binding_delta
 UNION SELECT owner,namespace,name FROM cr_binding_lookup_new
 UNION SELECT glob.target_owner,name.namespace,name.name FROM cr_binding_globs glob
 CROSS JOIN cr_binding_name_delta name ON name.owner=glob.owner
 UNION SELECT glob.owner,target.namespace,target.name FROM cr_binding_globs glob
 CROSS JOIN cr_binding_delta target ON target.owner=glob.target_owner
 WHERE NOT EXISTS(SELECT 1 FROM cr_binding_masks mask WHERE mask.owner=glob.owner AND mask.name<>target.name)
 UNION SELECT owner.parent_owner,name.namespace,name.name FROM cr_binding_name_delta name
 CROSS JOIN cr_binding_owners owner ON owner.owner=name.owner WHERE owner.parent_owner IS NOT NULL";

pub(super) const PATHS_SQL: &str = "INSERT OR IGNORE INTO cr_binding_paths
 SELECT path.blob_id,path.import_ordinal,path.module_path,path.position+1,destination.owner
 FROM cr_binding_path_delta path CROSS JOIN cr_binding_segments segment
 ON segment.blob_id=path.blob_id AND segment.import_ordinal=path.import_ordinal AND segment.ordinal=path.position
 CROSS JOIN cr_binding_owners current ON current.owner=path.owner
 CROSS JOIN cr_binding_owners destination ON destination.blob_id=0 AND destination.binder_scope=0
 AND destination.crate_key=current.crate_key AND destination.module_path=CASE
 WHEN segment.segment='crate' AND path.position=0 THEN 'crate'
 WHEN segment.segment='self' THEN current.module_path
 WHEN segment.segment='super' THEN (SELECT parent_module_path FROM cr_members member
 WHERE member.module_path=current.module_path AND member.placement<>'include' LIMIT 1) END
 WHERE segment.segment IN ('crate','self','super')
 UNION ALL
 SELECT binding.blob_id,binding.import_ordinal,binding.module_path,binding.position+1,destination.owner
 FROM cr_binding_delta_reads binding CROSS JOIN cr_binding_segments segment
 ON segment.blob_id=binding.blob_id AND segment.import_ordinal=binding.import_ordinal
 AND segment.ordinal=binding.position AND segment.segment=binding.name
 CROSS JOIN cr_binding_owners current ON current.owner=binding.owner
 CROSS JOIN cr_binding_imports source ON source.blob_id=binding.blob_id
 AND source.import_ordinal=binding.import_ordinal AND source.module_path=binding.module_path
 CROSS JOIN cr_binding_owners requesting ON requesting.owner=source.owner
 CROSS JOIN cr_binding_owners destination ON destination.blob_id=0 AND destination.binder_scope=0
 AND destination.crate_key=binding.target_crate_key
 AND destination.module_path=CASE WHEN binding.target_name='self' THEN binding.target_module_path
 ELSE binding.target_module_path || '::' || binding.target_name END
 WHERE binding.namespace='type' AND segment.segment NOT IN ('crate','self','super')
 AND (binding.visibility='public' OR (requesting.crate_key=current.crate_key
 AND (requesting.module_path=CASE binding.visibility WHEN 'private' THEN current.module_path
 WHEN 'crate' THEN 'crate' ELSE binding.restricted_module_path END
 OR substr(requesting.module_path,1,length(CASE binding.visibility WHEN 'private' THEN current.module_path
 WHEN 'crate' THEN 'crate' ELSE binding.restricted_module_path END)+2)=
 CASE binding.visibility WHEN 'private' THEN current.module_path
 WHEN 'crate' THEN 'crate' ELSE binding.restricted_module_path END || '::')))";

pub(super) const GLOB_EDGES_SQL: &str = "INSERT OR IGNORE INTO cr_binding_globs
 SELECT destination.owner,path.owner FROM cr_binding_imports source
 CROSS JOIN cr_binding_paths path ON path.blob_id=source.blob_id AND path.import_ordinal=source.import_ordinal
 AND path.module_path=source.module_path AND path.position=source.segments
 CROSS JOIN cr_binding_destinations destination ON destination.blob_id=source.blob_id
 AND destination.import_ordinal=source.import_ordinal AND destination.module_path=source.module_path WHERE source.is_glob=1";

// All binding writes share accessibility, domain intersection and endpoint
// deduplication. Precedence is decided before a glob endpoint can enter.
pub(super) const ADMIT_SQL: &str = include_str!("rust_crate_export_fixpoint.sql");

pub(super) const FALLBACK_REQUESTS_SQL: &str = "INSERT OR IGNORE INTO cr_binding_fallback
 SELECT owner.owner,done.namespace,done.name FROM cr_binding_owners owner
 CROSS JOIN cr_binding_complete done ON done.owner=owner.owner
 WHERE owner.parent_owner IS NOT NULL AND NOT EXISTS(SELECT 1 FROM cr_binding_targets local
 WHERE local.owner=owner.owner AND local.namespace=done.namespace AND local.name=done.name)";

pub(super) const FALLBACK_SQL: &str = "INSERT OR IGNORE INTO cr_binding_targets
 SELECT owner.owner,target.namespace,target.name,target.target_crate_key,target.target_module_path,target.target_name,
 target.declaration_blob_id,target.declaration_site,target.origin,target.visibility,target.restricted_module_path
 FROM cr_binding_owners owner CROSS JOIN cr_binding_targets target ON target.owner=owner.parent_owner
 CROSS JOIN cr_binding_fallback done ON done.owner=owner.owner AND done.namespace=target.namespace AND done.name=target.name";

pub(super) const EDGES_SQL: &str = "SELECT node.node,edge.target,COALESCE(edge.negative,0) FROM cr_binding_nodes node LEFT JOIN cr_binding_edges edge ON edge.source=node.node ORDER BY node.node,edge.target";

pub(super) fn components(conn: &Connection) -> Result<()> {
    conn.prepare_cached(NODES_SQL)?.execute([])?;
    conn.prepare_cached(CLEAR_EDGES_SQL)?.execute([])?;
    conn.prepare_cached(DEPENDENCIES_SQL)?.execute([])?;
    let rows = conn
        .prepare_cached(EDGES_SQL)?
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, bool>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let ids = rows
        .iter()
        .map(|&(id, _, _)| id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let index = ids
        .iter()
        .enumerate()
        .map(|(i, &id)| (id, i))
        .collect::<HashMap<_, _>>();
    let graph = DenseUsizeGraph::new(
        ids.len(),
        rows.iter()
            .filter_map(|&(from, to, _)| to.map(|to| (index[&from], index[&to]))),
    );
    let cancellation = CancellationToken::new();
    let mut budget = CfgAlgorithmBudget::default();
    let components = strongly_connected_components(
        &graph,
        &mut CfgAlgorithmRequest::new(&mut budget, &cancellation),
    )
    .expect("uncancelled unbounded import component query completes")
    .components;
    conn.prepare_cached(CLEAR_COMPONENTS_SQL)?.execute([])?;
    let mut insert = conn.prepare_cached(INSERT_COMPONENT_SQL)?;
    for (component, members) in components.iter().enumerate() {
        for &member in members {
            insert.execute(params![ids[member], component as i64])?;
        }
    }
    Ok(())
}

pub(super) const PATH_COMPLETE_SQL: &str = "INSERT OR IGNORE INTO cr_binding_path_complete
 SELECT done.blob_id,done.import_ordinal,done.module_path,done.position+1
 FROM cr_binding_path_complete done CROSS JOIN cr_binding_segments segment
 ON segment.blob_id=done.blob_id AND segment.import_ordinal=done.import_ordinal AND segment.ordinal=done.position
 WHERE NOT EXISTS(SELECT 1 FROM cr_binding_lookups lookup WHERE lookup.blob_id=done.blob_id
 AND lookup.import_ordinal=done.import_ordinal AND lookup.module_path=done.module_path AND lookup.position=done.position
 AND NOT EXISTS(SELECT 1 FROM cr_binding_complete target WHERE target.owner=lookup.owner
 AND target.namespace=lookup.namespace AND target.name=lookup.name))";

pub(super) const IMPORT_COMPLETE_SQL: &str = "INSERT OR IGNORE INTO cr_binding_import_complete
 SELECT source.blob_id,source.import_ordinal,source.module_path,namespace.value
 FROM cr_binding_imports source CROSS JOIN json_each('[\"type\",\"value\",\"macro\"]') namespace
 CROSS JOIN cr_binding_path_complete done ON done.blob_id=source.blob_id AND done.import_ordinal=source.import_ordinal
 AND done.module_path=source.module_path AND done.position=source.segments
 WHERE NOT EXISTS(SELECT 1 FROM cr_binding_open_sources opened WHERE opened.blob_id=source.blob_id
 AND opened.import_ordinal=source.import_ordinal AND opened.module_path=source.module_path AND opened.namespace=namespace.value)
 AND (source.is_glob=1 OR NOT EXISTS(SELECT 1 FROM cr_binding_lookups lookup
 WHERE lookup.blob_id=source.blob_id AND lookup.import_ordinal=source.import_ordinal
 AND lookup.module_path=source.module_path AND lookup.position=source.segments AND lookup.namespace=namespace.value
 AND NOT EXISTS(SELECT 1 FROM cr_binding_complete target WHERE target.owner=lookup.owner
 AND target.namespace=lookup.namespace AND target.name=lookup.name)))";

pub(super) const DECLARATION_COMPLETE_SQL: &str = "INSERT OR IGNORE INTO cr_binding_complete
 SELECT target.owner,target.namespace,target.name FROM cr_binding_targets target
 WHERE target.origin='declaration'";

// Close an entire positive stratum together after propagation quiesces.
// Pending negative predecessors and open inputs block their positive dependents.
// This avoids rescanning every positive chain once per component; negative
// strata still re-enter propagation before their successors can close.
pub(super) const COMPLETE_SQL: &str = "INSERT OR IGNORE INTO cr_binding_complete
 WITH RECURSIVE settled AS MATERIALIZED (SELECT * FROM cr_binding_complete),
 blocked(component) AS (
 SELECT DISTINCT component.component FROM cr_binding_components component
 CROSS JOIN cr_binding_nodes key ON key.node=component.node
 CROSS JOIN cr_binding_owners owner ON owner.owner=key.owner
 WHERE NOT EXISTS(SELECT 1 FROM settled done WHERE done.owner=key.owner AND done.namespace=key.namespace AND done.name=key.name)
 AND ((owner.open<>0 AND NOT EXISTS(SELECT 1 FROM cr_binding_targets binding WHERE binding.owner=key.owner
 AND binding.namespace=key.namespace AND binding.name=key.name))
 OR EXISTS(SELECT 1 FROM cr_binding_open_names input WHERE input.owner=key.owner AND input.namespace=key.namespace AND input.name=key.name)
 OR EXISTS(SELECT 1 FROM cr_binding_edges edge CROSS JOIN cr_binding_components target_component ON target_component.node=edge.target
 CROSS JOIN cr_binding_nodes target ON target.node=edge.target
 WHERE edge.source=key.node AND edge.negative=1 AND (target_component.component=component.component
 OR NOT EXISTS(SELECT 1 FROM settled done WHERE done.owner=target.owner AND done.namespace=target.namespace AND done.name=target.name))))
 UNION SELECT consumer.component FROM blocked
 CROSS JOIN cr_binding_components dependency ON dependency.component=blocked.component
 CROSS JOIN cr_binding_edges edge INDEXED BY cr_binding_edges_target ON edge.target=dependency.node AND edge.negative=0
 CROSS JOIN cr_binding_components consumer ON consumer.node=edge.source
 )
 SELECT node.owner,node.namespace,node.name FROM cr_binding_nodes node
 CROSS JOIN cr_binding_components component ON component.node=node.node
 WHERE NOT EXISTS(SELECT 1 FROM blocked WHERE blocked.component=component.component)";

pub(super) const SELF_SQL: &str = "INSERT OR IGNORE INTO cr_binding_targets
 SELECT owner.owner,'type','self',owner.crate_key,owner.module_path,'self',0,0,'declaration',
 CASE WHEN declaration.visibility='private' AND declaration.module_path='crate' THEN 'crate'
 WHEN declaration.visibility='private' THEN 'restricted' ELSE COALESCE(declaration.visibility,'public') END,
 CASE WHEN declaration.visibility='private' AND declaration.module_path<>'crate' THEN declaration.module_path
 ELSE declaration.restricted_module_path END
 FROM cr_binding_owners owner
 LEFT JOIN cr_module_declarations module ON module.module_path=owner.module_path
 LEFT JOIN cr_enums enumeration ON enumeration.container_path=owner.module_path
 LEFT JOIN cr_exports declaration ON declaration.crate_key=owner.crate_key
 AND declaration.module_path=COALESCE(module.parent_module_path,enumeration.module_path)
 AND declaration.namespace='type' AND declaration.origin='declaration'
 AND (declaration.name=module.module_name OR (module.module_name IS NULL
 AND owner.module_path=declaration.module_path || '::' || declaration.name))
 WHERE owner.blob_id=0 AND owner.binder_scope=0";

pub(super) const OPEN_SQL: &str = "UPDATE cr_binding_owners AS owner SET open=1 WHERE
 EXISTS(SELECT 1 FROM cr_gaps gap WHERE gap.gap_kind IN ('open_export_inventory','unknown_activation','unresolved_visibility')
 AND gap.subject=owner.module_path)";

pub(super) const FOREIGN_SQL: &str = "INSERT OR IGNORE INTO cr_binding_targets
 SELECT owner.owner,export.namespace,export.name,export.target_crate_key,export.target_module_path,export.target_name,
 export.declaration_blob_id,export.declaration_site,export.origin,export.visibility,export.restricted_module_path
 FROM cr_binding_owners owner CROSS JOIN cr_foreign foreign_crate ON foreign_crate.crate_key=owner.crate_key
 CROSS JOIN rust_crate_exports export ON export.topology_id=foreign_crate.topology_id
 AND export.module_path=owner.module_path AND export.visibility='public'
 WHERE owner.blob_id=0 AND owner.binder_scope=0 AND (
 EXISTS(SELECT 1 FROM cr_binding_names demand WHERE demand.owner=owner.owner
 AND demand.namespace=export.namespace AND demand.name=export.name)
 OR EXISTS(SELECT 1 FROM cr_binding_globs glob WHERE glob.target_owner=owner.owner))";

// Conflict evidence preserves private members too: a consumer needs the whole
// group to decide whether its effective visibility is known from these facts.
pub(super) const FOREIGN_CONFLICT_SQL: &str = "INSERT OR IGNORE INTO cr_binding_targets
 SELECT owner.owner,json_extract(evidence.value,'$.namespace'),node.name,
 unhex(json_extract(target.value,'$.crate')),json_extract(target.value,'$.module'),json_extract(target.value,'$.name'),
 json_extract(target.value,'$.binding.blob'),json_extract(target.value,'$.binding.site'),
 json_extract(target.value,'$.binding.origin'),json_extract(target.value,'$.binding.visibility'),
 json_extract(target.value,'$.binding.restriction')
 FROM cr_binding_names node CROSS JOIN cr_binding_owners owner ON owner.owner=node.owner
 CROSS JOIN cr_foreign foreign_crate ON foreign_crate.crate_key=owner.crate_key
 CROSS JOIN rust_crate_gaps gap ON gap.topology_id=foreign_crate.topology_id
 AND gap.gap_kind='open_export_inventory' AND gap.subject=owner.module_path || '::' || node.name
 CROSS JOIN json_each(gap.detail,'$.evidence') evidence
 CROSS JOIN json_each(evidence.value,'$.targets') target
 WHERE json_extract(evidence.value,'$.reason')='InconsistentPrecedence'
 AND json_extract(evidence.value,'$.namespace')=node.namespace
 AND json_extract(evidence.value,'$.member_blob')=0
 AND json_extract(evidence.value,'$.binder_scope')=0
 AND json_extract(target.value,'$.binding.visibility') IS NOT NULL";

pub(super) const FOREIGN_OPEN_SQL: &str = "UPDATE cr_binding_owners AS owner SET open=1
 WHERE EXISTS(SELECT 1 FROM cr_foreign foreign_crate CROSS JOIN rust_crate_gaps gap
 ON gap.topology_id=foreign_crate.topology_id
 WHERE foreign_crate.crate_key=owner.crate_key
 AND gap.gap_kind IN ('open_export_inventory','unknown_activation','unresolved_visibility')
 AND gap.subject=owner.module_path)";

pub(super) const EXPORTS_SQL: &str = "INSERT OR IGNORE INTO cr_exports
 SELECT owner.crate_key,owner.module_path,target.namespace,target.name,target.origin,
 target.visibility,target.restricted_module_path,target.declaration_blob_id,target.declaration_site
 FROM cr_binding_exact_targets target CROSS JOIN cr_binding_owners owner ON owner.owner=target.owner
 CROSS JOIN cr_identity identity ON identity.crate_key=owner.crate_key
 WHERE owner.blob_id=0 AND owner.binder_scope=0 AND target.declaration_blob_id<>0
 AND (target.origin='declaration' OR target.visibility<>'private')";

pub(super) const ROUTES_SQL: &str = "INSERT OR IGNORE INTO cr_routes
 SELECT source.blob_id,source.import_ordinal,source.module_path,owner.crate_key,owner.module_path
 FROM cr_binding_imports source CROSS JOIN cr_binding_paths path
 ON path.blob_id=source.blob_id AND path.import_ordinal=source.import_ordinal
 AND path.module_path=source.module_path AND path.position=source.segments
 CROSS JOIN cr_binding_owners owner ON owner.owner=path.owner WHERE source.import_ordinal>=0";

// A partially accessible glob conflict has no fact-defined export visibility.
// Classify it only after the binding fixed point, without choosing an import
// order or withdrawing endpoints. Completeness and binding-flow dependencies
// both retain the uncertainty; only actual endpoints are excluded from exact
// publication, so an independent visible binding remains available.
pub(super) const UNCERTAIN_SQL: &str = "INSERT OR IGNORE INTO cr_binding_uncertain
 WITH RECURSIVE partial AS MATERIALIZED (
 SELECT consumer,provider,namespace,name FROM cr_binding_visibility_reads
 GROUP BY consumer,provider,namespace,name HAVING MIN(accessible)=0 AND MAX(accessible)=1
 AND MIN(origin)='glob_reexport' AND MAX(origin)='glob_reexport'
 ), affected(node,target_crate_key,target_module_path,target_name) AS (
 SELECT node.node,target.target_crate_key,target.target_module_path,target.target_name
 FROM partial CROSS JOIN cr_binding_nodes provider ON provider.owner=partial.provider
 AND provider.namespace=partial.namespace AND provider.name=partial.name
 CROSS JOIN cr_binding_edges edge INDEXED BY cr_binding_edges_target
 ON edge.target=provider.node AND edge.negative=0 AND edge.propagates_ambiguity=1
 CROSS JOIN cr_binding_nodes node ON node.node=edge.source AND node.owner=partial.consumer
 CROSS JOIN cr_binding_targets target ON target.owner=partial.provider
 AND target.namespace=partial.namespace AND target.name=partial.name
 UNION
 SELECT node.node,unhex(json_extract(target.value,'$.crate')),json_extract(target.value,'$.module'),json_extract(target.value,'$.name')
 FROM cr_binding_nodes node CROSS JOIN cr_binding_owners owner ON owner.owner=node.owner
 CROSS JOIN cr_foreign foreign_crate ON foreign_crate.crate_key=owner.crate_key
 CROSS JOIN rust_crate_gaps gap ON gap.topology_id=foreign_crate.topology_id
 AND gap.gap_kind='open_export_inventory' AND gap.subject=owner.module_path || '::' || node.name
 CROSS JOIN json_each(gap.detail,'$.evidence') evidence CROSS JOIN json_each(evidence.value,'$.targets') target
 WHERE json_extract(evidence.value,'$.reason')='UnsupportedGlobConflictVisibility'
 AND json_extract(evidence.value,'$.namespace')=node.namespace
 AND json_extract(evidence.value,'$.member_blob')=0 AND json_extract(evidence.value,'$.binder_scope')=0
 UNION
 SELECT edge.source,affected.target_crate_key,affected.target_module_path,affected.target_name
 FROM affected CROSS JOIN cr_binding_edges edge INDEXED BY cr_binding_edges_target ON edge.target=affected.node
 WHERE edge.negative=1 OR edge.propagates_ambiguity=1
 ) SELECT * FROM affected";

// An endpoint can have both an uncertain source and an independent exact
// witness. Keep that witness even when endpoint deduplication merged the rows.
// This finite positive proof closure runs once, after the canonical fixed
// point: no binding is withdrawn and no per-round relation is recomputed.
pub(super) const CERTAIN_SQL: &str = "INSERT OR IGNORE INTO cr_binding_certain
 WITH RECURSIVE partial AS MATERIALIZED (
 SELECT consumer,provider,namespace,name FROM cr_binding_visibility_reads
 GROUP BY consumer,provider,namespace,name HAVING MIN(accessible)=0 AND MAX(accessible)=1
 AND MIN(origin)='glob_reexport' AND MAX(origin)='glob_reexport'
 ), proof(node,target_crate_key,target_module_path,target_name) AS (
 SELECT node.node,target.target_crate_key,target.target_module_path,target.target_name
 FROM cr_binding_targets target CROSS JOIN cr_binding_nodes node
 ON node.owner=target.owner AND node.namespace=target.namespace AND node.name=target.name
 WHERE target.origin='declaration' OR NOT EXISTS(SELECT 1 FROM cr_binding_uncertain uncertain
 WHERE uncertain.node=node.node AND uncertain.target_crate_key=target.target_crate_key
 AND uncertain.target_module_path=target.target_module_path AND uncertain.target_name=target.target_name)
 UNION
 SELECT consumer.node,target.target_crate_key,target.target_module_path,target.target_name
 FROM proof CROSS JOIN cr_binding_edges edge INDEXED BY cr_binding_edges_target
 ON edge.target=proof.node AND edge.negative=0 AND edge.propagates_ambiguity=1
 CROSS JOIN cr_binding_nodes consumer ON consumer.node=edge.source
 CROSS JOIN cr_binding_nodes provider ON provider.node=edge.target
 CROSS JOIN cr_binding_targets target ON target.owner=consumer.owner
 AND target.namespace=consumer.namespace AND target.name=consumer.name
 AND target.target_crate_key=proof.target_crate_key AND target.target_module_path=proof.target_module_path AND target.target_name=proof.target_name
 WHERE NOT EXISTS(SELECT 1 FROM partial WHERE partial.consumer=consumer.owner AND partial.provider=provider.owner
 AND partial.namespace=provider.namespace AND partial.name=provider.name)
 ) SELECT * FROM proof";

pub(super) const MIXED_VISIBILITY_SQL: &str = "INSERT INTO cr_gaps
 SELECT 'open_export_inventory',owner.module_path || '::' || node.name,
 json_object('subject_level','binding','reason','UnsupportedGlobConflictVisibility','namespace',node.namespace,
 'member_blob',owner.blob_id,'binder_scope',owner.binder_scope,
 'detail','a glob conflict group with mixed member visibility, whose export depends on rustc''s import resolution order',
 'exact_targets',json((SELECT json_group_array(json_object('crate',hex(proof.target_crate_key),
 'module',proof.target_module_path,'name',proof.target_name)
 ORDER BY proof.target_crate_key,proof.target_module_path,proof.target_name)
 FROM cr_binding_certain proof WHERE proof.node=node.node)),
 'targets',json_group_array(json_object('crate',hex(uncertain.target_crate_key),'module',uncertain.target_module_path,'name',uncertain.target_name)
 ORDER BY uncertain.target_crate_key,uncertain.target_module_path,uncertain.target_name))
 FROM cr_binding_uncertain uncertain CROSS JOIN cr_binding_nodes node ON node.node=uncertain.node
 CROSS JOIN cr_binding_owners owner ON owner.owner=node.owner
 CROSS JOIN cr_identity identity ON identity.crate_key=owner.crate_key
 WHERE node.name<>'self' AND NOT EXISTS(SELECT 1 FROM cr_binding_masks mask WHERE mask.owner=node.owner)
 GROUP BY node.node";

pub(super) const AMBIGUITY_SQL: &str = "INSERT INTO cr_gaps
 WITH RECURSIVE choices AS MATERIALIZED (
 SELECT owner,namespace,name,target_crate_key,target_module_path,target_name FROM cr_binding_exact_targets
 UNION SELECT owner,namespace,name,target_crate_key,target_module_path,target_name FROM cr_binding_prelude_reads
 ), affected(node) AS (
 SELECT node.node FROM choices target CROSS JOIN cr_binding_nodes node
 ON node.owner=target.owner AND node.namespace=target.namespace AND node.name=target.name
 GROUP BY node.node HAVING COUNT(*)>1
 UNION SELECT node.node FROM cr_binding_nodes node
 CROSS JOIN cr_binding_owners owner ON owner.owner=node.owner
 CROSS JOIN cr_foreign foreign_crate ON foreign_crate.crate_key=owner.crate_key
 CROSS JOIN rust_crate_gaps gap ON gap.topology_id=foreign_crate.topology_id
 AND gap.gap_kind='open_export_inventory' AND gap.subject=owner.module_path || '::' || node.name
 CROSS JOIN json_each(gap.detail,'$.evidence') evidence
 WHERE json_extract(evidence.value,'$.reason')='InconsistentPrecedence'
 AND (json_extract(evidence.value,'$.namespace') IS NULL OR json_extract(evidence.value,'$.namespace')=node.namespace)
 AND (json_extract(evidence.value,'$.binder_scope') IS NULL OR json_extract(evidence.value,'$.member_blob')=0)
 UNION SELECT edge.source FROM affected CROSS JOIN cr_binding_edges edge INDEXED BY cr_binding_edges_target
 ON edge.target=affected.node AND edge.negative=0 AND edge.propagates_ambiguity=1
 )
 SELECT 'open_export_inventory',owner.module_path || '::' || node.name,
 json_object('subject_level','binding','reason','InconsistentPrecedence','namespace',node.namespace,
 'member_blob',owner.blob_id,'binder_scope',owner.binder_scope,
 'dependency_ambiguity',json(CASE WHEN (SELECT COUNT(*) FROM choices target
 WHERE target.owner=node.owner AND target.namespace=node.namespace AND target.name=node.name)<2 THEN 'true' ELSE 'false' END),
 'targets',json((SELECT json_group_array(json_object('crate',hex(target.target_crate_key),'module',target.target_module_path,'name',target.target_name,
 'binding',json((SELECT json_object('origin',witness.origin,'visibility',witness.visibility,
 'restriction',witness.restricted_module_path,'blob',witness.declaration_blob_id,'site',witness.declaration_site)
 FROM cr_binding_targets witness WHERE witness.owner=target.owner AND witness.namespace=target.namespace AND witness.name=target.name
 AND witness.target_crate_key=target.target_crate_key AND witness.target_module_path=target.target_module_path AND witness.target_name=target.target_name)))
 ORDER BY target.target_crate_key,target.target_module_path,target.target_name)
 FROM choices target WHERE target.owner=node.owner AND target.namespace=node.namespace AND target.name=node.name)))
 FROM affected CROSS JOIN cr_binding_nodes node ON node.node=affected.node
 CROSS JOIN cr_binding_owners owner ON owner.owner=node.owner
 CROSS JOIN cr_identity identity ON identity.crate_key=owner.crate_key
 WHERE node.name<>'self' AND NOT EXISTS(SELECT 1 FROM cr_binding_masks mask WHERE mask.owner=node.owner)
 AND (NOT EXISTS(SELECT 1 FROM cr_binding_uncertain uncertain WHERE uncertain.node=node.node)
 OR (SELECT COUNT(*) FROM choices target WHERE target.owner=node.owner AND target.namespace=node.namespace AND target.name=node.name)>1)";

// Preserve the originating invocation through dependency edges. A modeled
// expansion can discharge exactly that inventory, while any other inventory
// or boundary remains an independent obligation.
pub(super) const PENDING_SQL: &str = "INSERT INTO cr_gaps
 WITH RECURSIVE inventories(owner,inventory) AS (
 SELECT owner.owner,CASE WHEN json_extract(gap.detail,'$.reason')='UnsupportedMacroGeneratedModule' THEN gap.detail ELSE 'null' END
 FROM cr_binding_owners owner CROSS JOIN cr_identity identity ON identity.crate_key=owner.crate_key
 CROSS JOIN cr_gaps gap ON gap.subject=owner.module_path
 AND gap.gap_kind IN ('open_export_inventory','unknown_activation','unresolved_visibility')
 UNION
 SELECT owner.owner,CASE WHEN json_extract(evidence.value,'$.reason')='UnsupportedMacroGeneratedModule' THEN evidence.value ELSE 'null' END
 FROM cr_binding_owners owner CROSS JOIN cr_foreign foreign_crate ON foreign_crate.crate_key=owner.crate_key
 CROSS JOIN rust_crate_gaps gap ON gap.topology_id=foreign_crate.topology_id AND gap.subject=owner.module_path
 AND gap.gap_kind IN ('open_export_inventory','unknown_activation','unresolved_visibility')
 CROSS JOIN json_each(gap.detail,'$.evidence') evidence
 ), opened(node,boundary,inventory) AS (
 SELECT node.node,'workspace_local',COALESCE(inventories.inventory,'null')
 FROM cr_binding_nodes node CROSS JOIN cr_binding_owners owner ON owner.owner=node.owner
 LEFT JOIN inventories ON inventories.owner=owner.owner
 WHERE owner.open<>0 AND NOT EXISTS(SELECT 1 FROM cr_binding_complete done WHERE done.owner=node.owner AND done.namespace=node.namespace AND done.name=node.name)
 UNION SELECT node.node,input.boundary,input.inventory FROM cr_binding_nodes node CROSS JOIN cr_binding_open_names input
 ON input.owner=node.owner AND input.namespace=node.namespace AND input.name=node.name AND input.reason<>'CyclicExpansion'
 WHERE NOT EXISTS(SELECT 1 FROM cr_binding_complete done WHERE done.owner=node.owner AND done.namespace=node.namespace AND done.name=node.name)
 UNION SELECT edge.source,opened.boundary,opened.inventory FROM opened CROSS JOIN cr_binding_edges edge ON edge.target=opened.node
 ), external_paths(node,blob_id,import_ordinal,module_path) AS (
 SELECT node.node,source.blob_id,source.import_ordinal,source.module_path
 FROM cr_binding_open_sources opened CROSS JOIN cr_binding_imports source
 ON source.blob_id=opened.blob_id AND source.import_ordinal=opened.import_ordinal
 AND source.module_path=opened.module_path AND source.is_glob=0
 CROSS JOIN cr_binding_destinations destination ON destination.blob_id=source.blob_id
 AND destination.import_ordinal=source.import_ordinal AND destination.module_path=source.module_path
 CROSS JOIN cr_binding_nodes node ON node.owner=destination.owner
 AND node.namespace=opened.namespace AND node.name=source.bound_name
 UNION SELECT edge.source,path.blob_id,path.import_ordinal,path.module_path
 FROM external_paths path CROSS JOIN cr_binding_edges edge ON edge.target=path.node
 )
 SELECT DISTINCT 'open_export_inventory',owner.module_path || '::' || node.name,
 json_object('subject_level','binding','reason',CASE WHEN opened.node IS NOT NULL THEN 'OpenBoundary' ELSE 'CyclicExpansion' END,
 'boundary',opened.boundary,'namespace',node.namespace,'member_blob',owner.blob_id,'binder_scope',owner.binder_scope,
 'inventory',json(opened.inventory),
 'import_paths',json((SELECT json_group_array(json(route.path)) FROM (
 SELECT (SELECT json_group_array(segment) FROM (
 SELECT segment.ordinal,segment.segment FROM cr_binding_segments segment
 WHERE segment.blob_id=path.blob_id AND segment.import_ordinal=path.import_ordinal
 UNION ALL SELECT 2147483647,source.imported_name WHERE source.imported_name<>'self'
 ORDER BY 1)) AS path
 FROM external_paths path CROSS JOIN cr_binding_imports source
 ON source.blob_id=path.blob_id AND source.import_ordinal=path.import_ordinal
 AND source.module_path=path.module_path WHERE path.node=node.node) route)))
 FROM cr_binding_nodes node CROSS JOIN cr_binding_owners owner ON owner.owner=node.owner
 CROSS JOIN cr_identity identity ON identity.crate_key=owner.crate_key
 LEFT JOIN opened ON opened.node=node.node
 WHERE node.name<>'self' AND NOT EXISTS(SELECT 1 FROM cr_binding_masks mask WHERE mask.owner=node.owner)
 AND NOT EXISTS(SELECT 1 FROM cr_binding_complete done WHERE done.owner=node.owner AND done.namespace=node.namespace AND done.name=node.name)";

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub static EXTRA_COVERING_INDEX: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub(super) fn derive(conn: &Connection, edition: &str, _crate_name: &str, cfg: &str) -> Result<()> {
    #[cfg(any(test, feature = "test-support"))]
    if EXTRA_COVERING_INDEX.load(std::sync::atomic::Ordering::SeqCst) {
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS cr_binding_targets_covering
 ON cr_binding_targets(owner,namespace,name,target_module_path DESC,target_crate_key,target_name,
 visibility,restricted_module_path,origin,declaration_blob_id,declaration_site)",
        )?;
    }
    conn.execute_batch(CLEAR_SQL)?;
    conn.execute_batch("CREATE TEMP TABLE IF NOT EXISTS cr_authority_local_seeds AS SELECT * FROM cr_binding_targets WHERE 0;
 DELETE FROM cr_authority_local_seeds;")?;
    for sql in [
        OWNERS_SQL,
        super::binding_authority::LOCAL_OWNERS_SQL,
        PARENTS_SQL,
        LEXICAL_PARENTS_SQL,
        super::binding_authority::LOCAL_PARENTS_SQL,
        IMPORTS_SQL,
        GENERIC_SOURCES_SQL,
        ROUTE_SOURCES_SQL,
        SEGMENTS_SQL,
        MASK_OWNERS_SQL,
        MASKS_SQL,
        DESTINATIONS_SQL,
        SEED_SQL,
        MACRO_SEED_SQL,
        SELF_SQL,
        MASK_SEED_SQL,
        SEED_DEMANDS_SQL,
        OPEN_SQL,
        FOREIGN_OPEN_SQL,
        SEED_PATH_COMPLETE_SQL,
    ] {
        conn.prepare_cached(sql)?.execute([])?;
    }
    conn.execute(super::binding_authority::LOCAL_DECLARATIONS_SQL, [cfg])?;
    conn.execute(
        "INSERT OR IGNORE INTO cr_binding_targets SELECT * FROM cr_authority_local_seeds",
        [],
    )?;
    let absolute_anchor = crate::analyzer::resolution::root_import_anchor_semantic_identity(
        brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportAnchor::Absolute,
    )
    .fragment_local_digest();
    conn.prepare_cached(ABSOLUTE_SOURCES_SQL)?
        .execute([absolute_anchor.as_slice()])?;
    conn.prepare_cached(SEED_PATHS_SQL)?.execute([edition])?;
    #[cfg(any(test, feature = "test-support"))]
    let mut pass = 0;
    loop {
        let mut changed = 0;
        loop {
            conn.execute_batch(ADVANCE_DELTA_SQL)?;
            #[cfg(any(test, feature = "test-support"))]
            let started = std::time::Instant::now();
            #[cfg(any(test, feature = "test-support"))]
            let delta_rows = super::temp_table_rows(conn, "cr_binding_delta")?;
            #[cfg(any(test, feature = "test-support"))]
            let source_rows = super::temp_table_rows(conn, "cr_binding_imports")?;
            #[cfg(any(test, feature = "test-support"))]
            let (mut export_written, mut export_steps, mut route_steps) = (0, 0, 0);
            let mut added = 0;
            for sql in [
                LOOKUPS_SQL,
                DEMANDS_SQL,
                GAP_NAMES_SQL,
                FOREIGN_SQL,
                FOREIGN_CONFLICT_SQL,
                FOREIGN_MACRO_SQL,
                FOREIGN_ROOT_SQL,
                PATHS_SQL,
                GLOB_EDGES_SQL,
                FALLBACK_REQUESTS_SQL,
                FALLBACK_SQL,
                SOURCE_OPEN_SQL,
                OPEN_NAMES_SQL,
                PRESENT_SQL,
                ADMIT_SQL,
                DECLARATION_COMPLETE_SQL,
                PATH_COMPLETE_SQL,
                IMPORT_COMPLETE_SQL,
            ] {
                let (written, _steps) = super::execute_with_vm_steps(conn, sql, [])?;
                added += written;
                #[cfg(any(test, feature = "test-support"))]
                if sql == ADMIT_SQL {
                    export_written += written;
                    export_steps += _steps;
                } else {
                    route_steps += _steps;
                }
            }
            #[cfg(any(test, feature = "test-support"))]
            if super::CAPTURE_ROUTE_PASS_METRICS.load(std::sync::atomic::Ordering::Relaxed) {
                super::EXPORT_FIXPOINT_PASS_METRICS
                    .lock()
                    .expect("export metrics lock")
                    .push((
                        _crate_name.to_owned(),
                        super::ExportFixpointPassMetrics {
                            pass,
                            delta_rows_read: delta_rows,
                            source_rows,
                            rows_written: export_written,
                            sqlite_vm_steps: export_steps,
                            elapsed_micros: u64::try_from(started.elapsed().as_micros())
                                .unwrap_or(u64::MAX),
                            derive_elapsed_micros: 0,
                        },
                    ));
                super::ROUTE_PASS_METRICS
                    .lock()
                    .expect("route metrics lock")
                    .push((
                        _crate_name.to_owned(),
                        super::RoutePassMetrics {
                            pass,
                            source_import_rows_read: source_rows,
                            reexport_step_rows_read: 0,
                            glob_step_rows_read: 0,
                            route_rows_written: added - export_written,
                            reexport_step_rows_written: 0,
                            reexport_closure_rows_deleted: 0,
                            reexport_closure_rows_written: 0,
                            glob_step_rows_written: 0,
                            glob_closure_rows_deleted: 0,
                            glob_closure_rows_written: 0,
                            sqlite_vm_steps: route_steps,
                            derive_elapsed_micros: 0,
                        },
                    ));
            }
            #[cfg(any(test, feature = "test-support"))]
            {
                pass += 1;
            }
            changed += added;
            if added == 0 {
                break;
            }
        }
        // Only after propagation quiesces: see MACRO_OPEN_NAMES_SQL.
        changed += conn.prepare_cached(MACRO_OPEN_NAMES_SQL)?.execute([])?;
        components(conn)?;
        let completed = conn.prepare_cached(COMPLETE_SQL)?.execute([])?;
        if completed == 0 && changed == 0 {
            break;
        }
    }
    for sql in [
        UNCERTAIN_SQL,
        CERTAIN_SQL,
        EXPORTS_SQL,
        ROUTES_SQL,
        AMBIGUITY_SQL,
        MIXED_VISIBILITY_SQL,
        PENDING_SQL,
    ] {
        conn.prepare_cached(sql)?.execute([])?;
    }
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn query_registry() -> Vec<(&'static str, &'static str, usize)> {
    vec![
        ("rust_binding_mask_owners_sql", MASK_OWNERS_SQL, 0),
        ("rust_binding_masks_sql", MASKS_SQL, 0),
        ("rust_binding_destinations_sql", DESTINATIONS_SQL, 0),
        ("rust_binding_mask_seed_sql", MASK_SEED_SQL, 0),
        ("rust_binding_seed_demands_sql", SEED_DEMANDS_SQL, 0),
        ("rust_binding_lookups_sql", LOOKUPS_SQL, 0),
        ("rust_binding_nodes_sql", NODES_SQL, 0),
        ("rust_binding_dependencies_sql", DEPENDENCIES_SQL, 0),
        ("rust_binding_owners", OWNERS_SQL, 0),
        ("rust_binding_parents", PARENTS_SQL, 0),
        ("rust_binding_lexical_parents", LEXICAL_PARENTS_SQL, 0),
        ("rust_binding_imports", IMPORTS_SQL, 0),
        ("rust_binding_seed", SEED_SQL, 0),
        ("rust_binding_macro_seed", MACRO_SEED_SQL, 0),
        ("rust_binding_open_names", OPEN_NAMES_SQL, 0),
        ("rust_binding_open_sources", SOURCE_OPEN_SQL, 0),
        ("rust_binding_generic_sources", GENERIC_SOURCES_SQL, 0),
        ("rust_binding_route_sources", ROUTE_SOURCES_SQL, 0),
        ("rust_binding_segments", SEGMENTS_SQL, 0),
        ("rust_binding_self", SELF_SQL, 0),
        ("rust_binding_open", OPEN_SQL, 0),
        ("rust_binding_foreign_open", FOREIGN_OPEN_SQL, 0),
        ("rust_binding_absolute_sources", ABSOLUTE_SOURCES_SQL, 1),
        ("rust_binding_seed_paths", SEED_PATHS_SQL, 1),
        ("rust_binding_seed_path_complete", SEED_PATH_COMPLETE_SQL, 0),
        ("rust_binding_demands", DEMANDS_SQL, 0),
        ("rust_binding_gap_names", GAP_NAMES_SQL, 0),
        ("rust_binding_macro_open_names", MACRO_OPEN_NAMES_SQL, 0),
        ("rust_binding_foreign", FOREIGN_SQL, 0),
        ("rust_binding_foreign_conflict", FOREIGN_CONFLICT_SQL, 0),
        ("rust_binding_foreign_macro", FOREIGN_MACRO_SQL, 0),
        ("rust_binding_foreign_root", FOREIGN_ROOT_SQL, 0),
        ("rust_binding_paths", PATHS_SQL, 0),
        ("rust_binding_glob_edges", GLOB_EDGES_SQL, 0),
        ("rust_binding_present", PRESENT_SQL, 0),
        ("rust_binding_admit", ADMIT_SQL, 0),
        ("rust_binding_path_complete", PATH_COMPLETE_SQL, 0),
        ("rust_binding_import_complete", IMPORT_COMPLETE_SQL, 0),
        (
            "rust_binding_declaration_complete",
            DECLARATION_COMPLETE_SQL,
            0,
        ),
        ("rust_binding_fallback_requests", FALLBACK_REQUESTS_SQL, 0),
        ("rust_binding_fallback", FALLBACK_SQL, 0),
        ("rust_binding_clear_edges", CLEAR_EDGES_SQL, 0),
        ("rust_binding_clear_components", CLEAR_COMPONENTS_SQL, 0),
        ("rust_binding_insert_component", INSERT_COMPONENT_SQL, 2),
        ("rust_binding_edges", EDGES_SQL, 0),
        ("rust_binding_complete", COMPLETE_SQL, 0),
        ("rust_binding_exports", EXPORTS_SQL, 0),
        ("rust_binding_routes", ROUTES_SQL, 0),
        ("rust_binding_uncertain", UNCERTAIN_SQL, 0),
        ("rust_binding_certain", CERTAIN_SQL, 0),
        ("rust_binding_mixed_visibility", MIXED_VISIBILITY_SQL, 0),
        ("rust_binding_ambiguity", AMBIGUITY_SQL, 0),
        ("rust_binding_pending", PENDING_SQL, 0),
    ]
}

// Negative ordinals are connection-local request identities, disjoint from
// producer import ordinals. All stored source keys are nonnegative u32 facts.
pub(super) const GENERIC_SOURCES_SQL: &str = "INSERT INTO cr_binding_imports
 SELECT source.blob_id,-1-4*source.route_key,source.module_path,owner.owner,0,NULL,source.target_name,
 'private',NULL,(SELECT COUNT(*) FROM cr_root_segments segment WHERE segment.blob_id=source.blob_id
 AND segment.route_key=source.route_key)
 FROM cr_root_sources source CROSS JOIN cr_identity identity
 CROSS JOIN cr_binding_owners owner ON owner.crate_key=identity.crate_key
 AND owner.module_path=source.module_path AND owner.blob_id=0 AND owner.binder_scope=0
 UNION ALL
 SELECT source.blob_id,-2-4*source.relation_key,source.module_path,owner.owner,0,NULL,source.subject_name,
 'private',NULL,source.subject_segments
 FROM cr_impl_sources source CROSS JOIN cr_identity identity
 CROSS JOIN cr_binding_owners owner ON owner.crate_key=identity.crate_key
 AND owner.module_path=source.module_path AND owner.blob_id=0 AND owner.binder_scope=0
 UNION ALL
 SELECT source.blob_id,-3-4*source.relation_key,source.module_path,owner.owner,0,NULL,source.trait_name,
 'private',NULL,source.trait_segments
 FROM cr_impl_sources source CROSS JOIN cr_identity identity
 CROSS JOIN cr_binding_owners owner ON owner.crate_key=identity.crate_key
 AND owner.module_path=source.module_path AND owner.blob_id=0 AND owner.binder_scope=0
 WHERE source.trait_name IS NOT NULL";

pub(super) const ROUTE_SOURCES_SQL: &str = "INSERT INTO cr_binding_route_sources
 SELECT 'source_rust_import_module_segments',blob_id,import_ordinal,module_path,import_ordinal
 FROM cr_source_imports
 UNION ALL SELECT 'cr_root_segments',blob_id,route_key,module_path,-1-4*route_key FROM cr_root_sources
 UNION ALL SELECT 'cr_impl_subject_segments',blob_id,relation_key,module_path,-2-4*relation_key FROM cr_impl_sources
 UNION ALL SELECT 'cr_impl_trait_segments',blob_id,relation_key,module_path,-3-4*relation_key FROM cr_impl_sources
 WHERE trait_name IS NOT NULL";

pub(super) const SEGMENTS_SQL: &str = "INSERT OR IGNORE INTO cr_binding_segments
 SELECT segment.blob_id,segment.import_ordinal,segment.ordinal,segment.segment
 FROM cr_source_imports source CROSS JOIN source_rust_import_module_segments segment
 ON segment.blob_id=source.blob_id AND segment.import_ordinal=source.import_ordinal
 UNION ALL SELECT segment.blob_id,-1-4*segment.route_key,segment.ordinal,segment.segment
 FROM cr_root_sources source CROSS JOIN cr_root_segments segment
 ON segment.blob_id=source.blob_id AND segment.route_key=source.route_key
 UNION ALL SELECT segment.blob_id,-2-4*segment.relation_key,segment.ordinal,segment.segment
 FROM cr_impl_sources source CROSS JOIN cr_impl_subject_segments segment
 ON segment.blob_id=source.blob_id AND segment.relation_key=source.relation_key
 UNION ALL SELECT segment.blob_id,-3-4*segment.relation_key,segment.ordinal,segment.segment
 FROM cr_impl_sources source CROSS JOIN cr_impl_trait_segments segment
 ON segment.blob_id=source.blob_id AND segment.relation_key=source.relation_key";

pub(super) const MACRO_SEED_SQL: &str = "INSERT OR IGNORE INTO cr_binding_targets
 SELECT owner.owner,item.namespace,item.name,owner.crate_key,item.module_path,item.name,
 0,0,'declaration',item.visibility,item.restricted_module_path
 FROM cr_macro_items item CROSS JOIN cr_identity identity
 CROSS JOIN cr_binding_owners owner ON owner.crate_key=identity.crate_key
 AND owner.module_path=item.module_path AND owner.blob_id=0 AND owner.binder_scope=0";

pub(super) const OPEN_NAMES_SQL: &str = "INSERT OR IGNORE INTO cr_binding_open_names(owner,namespace,name,boundary)
 SELECT destination.owner,opened.namespace,COALESCE(source.bound_name,name.name),'external_declared_unindexed'
 FROM cr_binding_open_sources opened CROSS JOIN cr_binding_imports source
 ON source.blob_id=opened.blob_id AND source.import_ordinal=opened.import_ordinal AND source.module_path=opened.module_path
 CROSS JOIN cr_binding_destinations destination ON destination.blob_id=source.blob_id
 AND destination.import_ordinal=source.import_ordinal AND destination.module_path=source.module_path
 LEFT JOIN cr_binding_names name ON source.is_glob=1 AND name.owner=destination.owner AND name.namespace=opened.namespace
 LEFT JOIN cr_binding_masks mask ON mask.owner=destination.owner
 WHERE (source.is_glob=0 AND source.bound_name IS NOT NULL) OR (source.is_glob=1 AND name.name IS NOT NULL
 AND (mask.owner IS NULL OR mask.name=name.name)
 AND NOT EXISTS(SELECT 1 FROM cr_binding_targets strong WHERE strong.owner=name.owner
 AND strong.namespace=name.namespace AND strong.name=name.name AND strong.origin IN ('declaration','reexport'))
 AND NOT EXISTS(SELECT 1 FROM cr_binding_imports named WHERE named.owner=source.owner
 AND named.is_glob=0 AND named.bound_name=name.name
 AND (mask.owner IS NULL OR named.blob_id<>mask.blob_id OR named.import_ordinal<>mask.import_ordinal OR named.module_path<>mask.module_path)
 AND (NOT EXISTS(SELECT 1 FROM cr_binding_import_complete complete WHERE complete.blob_id=named.blob_id
 AND complete.import_ordinal=named.import_ordinal AND complete.module_path=named.module_path AND complete.namespace=name.namespace)
 OR EXISTS(SELECT 1 FROM cr_binding_import_present present WHERE present.blob_id=named.blob_id
 AND present.import_ordinal=named.import_ordinal AND present.module_path=named.module_path AND present.namespace=name.namespace))))";

const ADVANCE_DELTA_SQL: &str = "DELETE FROM cr_binding_delta;
 INSERT INTO cr_binding_delta SELECT * FROM cr_binding_delta_next;
 DELETE FROM cr_binding_delta_next;
 DELETE FROM cr_binding_path_delta;
 INSERT INTO cr_binding_path_delta SELECT * FROM cr_binding_path_next;
 DELETE FROM cr_binding_path_next;
 DELETE FROM cr_binding_name_delta;
 INSERT INTO cr_binding_name_delta SELECT * FROM cr_binding_name_next;
 DELETE FROM cr_binding_name_next;
 DELETE FROM cr_binding_lookup_new;";

pub(super) const FOREIGN_MACRO_SQL: &str = "INSERT OR IGNORE INTO cr_binding_targets
 SELECT owner.owner,item.namespace,item.name,owner.crate_key,item.module_path,item.name,
 0,0,'declaration',item.visibility,item.restricted_module_path
 FROM cr_binding_owners owner CROSS JOIN cr_foreign foreign_crate ON foreign_crate.crate_key=owner.crate_key
 CROSS JOIN rust_crate_macro_items item ON item.topology_id=foreign_crate.topology_id
 AND item.module_path=owner.module_path AND item.visibility='public'
 WHERE owner.blob_id=0 AND owner.binder_scope=0 AND (
 EXISTS(SELECT 1 FROM cr_binding_names demand WHERE demand.owner=owner.owner
 AND demand.namespace=item.namespace AND demand.name=item.name)
 OR EXISTS(SELECT 1 FROM cr_binding_globs glob WHERE glob.target_owner=owner.owner))";

// Presence is independent of the publication frontier. A determined named
// source with an endpoint queued for publication still blocks every glob in
// that namespace; absence is concluded only after both facts are settled.
pub(super) const PRESENT_SQL: &str = "INSERT OR IGNORE INTO cr_binding_import_present
 SELECT source.blob_id,source.import_ordinal,source.module_path,target.namespace
 FROM cr_binding_imports source
 CROSS JOIN cr_binding_paths path ON path.blob_id=source.blob_id
 AND path.import_ordinal=source.import_ordinal AND path.module_path=source.module_path
 AND path.position=source.segments
 CROSS JOIN cr_binding_delta_reads target ON target.blob_id=path.blob_id AND target.import_ordinal=path.import_ordinal
 AND target.module_path=path.module_path AND target.position=path.position AND target.name=source.imported_name
 CROSS JOIN cr_binding_owners owner ON owner.owner=source.owner
 CROSS JOIN cr_binding_owners exporting ON exporting.owner=target.owner
 WHERE source.is_glob=0 AND source.bound_name IS NOT NULL
 AND (target.visibility='public' OR (owner.crate_key=exporting.crate_key
 AND (owner.module_path=CASE target.visibility WHEN 'private' THEN exporting.module_path
 WHEN 'crate' THEN 'crate' ELSE target.restricted_module_path END
 OR substr(owner.module_path,1,length(CASE target.visibility WHEN 'private' THEN exporting.module_path
 WHEN 'crate' THEN 'crate' ELSE target.restricted_module_path END)+2)=
 CASE target.visibility WHEN 'private' THEN exporting.module_path
 WHEN 'crate' THEN 'crate' ELSE target.restricted_module_path END || '::')))
";

pub(super) const FOREIGN_ROOT_SQL: &str = "INSERT OR IGNORE INTO cr_binding_targets
 SELECT owner.owner,'type',route.bound_name,route.target_crate_key,route.target_module_path,'self',
 0,0,'reexport',route.visibility,route.restricted_module_path
 FROM cr_binding_owners owner CROSS JOIN cr_foreign foreign_crate ON foreign_crate.crate_key=owner.crate_key
 CROSS JOIN rust_crate_reexport_routes route ON route.topology_id=foreign_crate.topology_id
 AND route.module_path=owner.module_path AND route.target_name='self' AND route.visibility='public'
 WHERE owner.blob_id=0 AND owner.binder_scope=0";

pub(super) const GAP_NAMES_SQL: &str = "-- Module inventory can share a path with a parent binding; only binding-level gaps open names.
INSERT INTO cr_binding_open_names
 SELECT name.owner,name.namespace,name.name,'OpenBoundary',COALESCE(json_extract(gap.detail,'$.boundary'),'workspace_local'),
 COALESCE(json_extract(gap.detail,'$.inventory'),'null')
 FROM cr_binding_names name CROSS JOIN cr_binding_owners owner ON owner.owner=name.owner
 CROSS JOIN cr_identity identity ON identity.crate_key=owner.crate_key
 CROSS JOIN cr_gaps gap ON gap.subject=owner.module_path || '::' || name.name
 AND gap.gap_kind IN ('open_export_inventory','unknown_activation')
 WHERE json_extract(gap.detail,'$.subject_level')='binding'
 AND (json_extract(gap.detail,'$.namespace') IS NULL OR json_extract(gap.detail,'$.namespace')=name.namespace)
 UNION
 SELECT name.owner,name.namespace,name.name,
 CASE WHEN json_extract(evidence.value,'$.reason')='CyclicExpansion' THEN 'CyclicExpansion' ELSE 'OpenBoundary' END,COALESCE(json_extract(evidence.value,'$.boundary'),'workspace_local'),
 COALESCE(json_extract(evidence.value,'$.inventory'),'null')
 FROM cr_binding_names name CROSS JOIN cr_binding_owners owner ON owner.owner=name.owner
 CROSS JOIN cr_foreign foreign_crate ON foreign_crate.crate_key=owner.crate_key
 CROSS JOIN rust_crate_gaps gap ON gap.topology_id=foreign_crate.topology_id
 AND gap.subject=owner.module_path || '::' || name.name
 AND gap.gap_kind IN ('open_export_inventory','unknown_activation')
 CROSS JOIN json_each(gap.detail,'$.evidence') evidence
 WHERE json_extract(evidence.value,'$.subject_level')='binding'
 AND json_extract(evidence.value,'$.reason') IS NOT 'InconsistentPrecedence'
 AND json_extract(evidence.value,'$.reason') IS NOT 'UnsupportedGlobConflictVisibility'
 AND (json_extract(evidence.value,'$.namespace') IS NULL OR json_extract(evidence.value,'$.namespace')=name.namespace)
 AND (json_extract(evidence.value,'$.binder_scope') IS NULL OR json_extract(evidence.value,'$.member_blob')=0)
 ON CONFLICT DO NOTHING";

pub(super) const MASK_OWNERS_SQL: &str = "INSERT INTO cr_binding_owners(crate_key,module_path,blob_id,binder_scope,parent_owner)
 SELECT owner.crate_key,owner.module_path,owner.blob_id,-1-row_number() OVER(ORDER BY source.blob_id,source.import_ordinal,source.module_path),owner.parent_owner
 FROM cr_binding_imports source CROSS JOIN cr_binding_owners owner ON owner.owner=source.owner
 WHERE source.is_glob=0 AND source.bound_name IS NOT NULL";

pub(super) const MASKS_SQL: &str = "INSERT INTO cr_binding_masks
 SELECT masked.owner,source.owner,source.blob_id,source.import_ordinal,source.module_path,source.bound_name
 FROM (SELECT source.*, -1-row_number() OVER(ORDER BY blob_id,import_ordinal,module_path) AS mask_scope
 FROM cr_binding_imports source WHERE source.is_glob=0 AND source.bound_name IS NOT NULL) source
 CROSS JOIN cr_binding_owners base ON base.owner=source.owner
 CROSS JOIN cr_binding_owners masked ON masked.crate_key=base.crate_key AND masked.module_path=base.module_path
 AND masked.blob_id=base.blob_id AND masked.binder_scope=source.mask_scope";

pub(super) const DESTINATIONS_SQL: &str = "INSERT INTO cr_binding_destinations
 SELECT blob_id,import_ordinal,module_path,owner FROM cr_binding_imports
 UNION SELECT source.blob_id,source.import_ordinal,source.module_path,mask.owner
 FROM cr_binding_masks mask CROSS JOIN cr_binding_imports source ON source.owner=mask.base_owner
 WHERE (source.is_glob=1 OR source.bound_name=mask.name)
 AND (source.blob_id<>mask.blob_id OR source.import_ordinal<>mask.import_ordinal OR source.module_path<>mask.module_path)";

pub(super) const MASK_SEED_SQL: &str = "INSERT OR IGNORE INTO cr_binding_targets
 SELECT mask.owner,target.namespace,target.name,target.target_crate_key,target.target_module_path,target.target_name,
 target.declaration_blob_id,target.declaration_site,target.origin,target.visibility,target.restricted_module_path
 FROM cr_binding_masks mask CROSS JOIN cr_binding_targets target ON target.owner=mask.base_owner
 AND target.name=mask.name AND target.origin='declaration' ";

pub(super) const LOOKUPS_SQL: &str = "INSERT OR IGNORE INTO cr_binding_lookups
 SELECT path.blob_id,path.import_ordinal,path.module_path,path.position,
 CASE WHEN path.owner=source.owner AND name.name=source.bound_name THEN COALESCE(mask.owner,path.owner) ELSE path.owner END,
 name.namespace,name.name
 FROM cr_binding_path_delta path CROSS JOIN cr_binding_imports source
 ON source.blob_id=path.blob_id AND source.import_ordinal=path.import_ordinal AND source.module_path=path.module_path
 LEFT JOIN cr_binding_masks mask ON mask.blob_id=source.blob_id AND mask.import_ordinal=source.import_ordinal AND mask.module_path=source.module_path
 CROSS JOIN (SELECT path.blob_id,path.import_ordinal,path.module_path,path.position,'type' AS namespace,segment.segment AS name
 FROM cr_binding_path_delta path CROSS JOIN cr_binding_segments segment ON segment.blob_id=path.blob_id
 AND segment.import_ordinal=path.import_ordinal AND segment.ordinal=path.position WHERE segment.segment NOT IN ('crate','self','super')
 UNION SELECT path.blob_id,path.import_ordinal,path.module_path,path.position,namespace.value,source.imported_name
 FROM cr_binding_path_delta path CROSS JOIN cr_binding_imports source ON source.blob_id=path.blob_id
 AND source.import_ordinal=path.import_ordinal AND source.module_path=path.module_path AND path.position=source.segments
 CROSS JOIN json_each('[\"type\",\"value\",\"macro\"]') namespace WHERE source.is_glob=0 AND source.imported_name IS NOT NULL) name
 ON name.blob_id=path.blob_id AND name.import_ordinal=path.import_ordinal AND name.module_path=path.module_path AND name.position=path.position";

pub(super) const NODES_SQL: &str = "INSERT OR IGNORE INTO cr_binding_nodes(owner,namespace,name) SELECT owner,namespace,name FROM cr_binding_names";

// The external-root arm makes a name bound by an import rooted at an unindexed
// crate wait for that root lookup. A glob binds every name of its destination,
// including the root spelling itself; the root never waits on its own import,
// since an import's path cannot resolve through that import's result (#6136:
// `use std::..::*` left `std` and every glob name pending as a cycle).
// Beyond that self-root case, a glob's contribution to a name that another
// import of the same module uses as such a first segment does not wait
// either: rustc resolves an import's path without the import itself, and a
// glob that supplied another import's extern root would be rejected (E0659, a
// glob against an outer scope during import resolution). Otherwise
// `use std::x::*; use dep::y::*;` makes `std` and `dep` wait on each other's
// absence, a cycle that never closes.
pub(super) const DEPENDENCIES_SQL: &str = "INSERT OR IGNORE INTO cr_binding_edges
 WITH dependencies(owner,namespace,name,target_owner,target_namespace,target_name,negative,propagates_ambiguity) AS (
 SELECT glob.owner,name.namespace,name.name,glob.target_owner,name.namespace,name.name,0,
 EXISTS(SELECT 1 FROM cr_binding_carries carried WHERE carried.owner=glob.owner
 AND carried.target_owner=glob.target_owner AND carried.namespace=name.namespace AND carried.name=name.name)
 FROM cr_binding_globs glob CROSS JOIN cr_binding_names name ON name.owner=glob.owner
 WHERE NOT EXISTS(SELECT 1 FROM cr_binding_targets strong WHERE strong.owner=glob.owner
 AND strong.namespace=name.namespace AND strong.name=name.name AND strong.origin IN ('declaration','reexport'))
 UNION SELECT destination.owner,name.namespace,name.name,lookup.owner,lookup.namespace,lookup.name,0,
 CASE WHEN source.is_glob=0 THEN 1 ELSE EXISTS(
 SELECT 1 FROM cr_binding_paths terminal CROSS JOIN cr_binding_carries carried
 ON carried.owner=destination.owner AND carried.target_owner=terminal.owner
 AND carried.namespace=name.namespace AND carried.name=name.name
 WHERE terminal.blob_id=source.blob_id AND terminal.import_ordinal=source.import_ordinal
 AND terminal.module_path=source.module_path AND terminal.position=source.segments) END
 FROM cr_binding_destinations destination CROSS JOIN cr_binding_imports source
 ON source.blob_id=destination.blob_id AND source.import_ordinal=destination.import_ordinal AND source.module_path=destination.module_path
 CROSS JOIN cr_binding_names name ON name.owner=destination.owner
 AND (source.is_glob=1 OR name.name=source.bound_name)
 CROSS JOIN cr_binding_lookups lookup ON lookup.blob_id=source.blob_id AND lookup.import_ordinal=source.import_ordinal
 AND lookup.module_path=source.module_path
 AND (lookup.position<source.segments OR lookup.namespace=name.namespace)
 WHERE NOT EXISTS(SELECT 1 FROM cr_binding_targets item WHERE item.owner=name.owner
 AND item.namespace=name.namespace AND item.name=name.name
 AND (item.origin='declaration' OR (source.is_glob=1 AND item.origin='reexport')))
 UNION SELECT name.owner,name.namespace,name.name,lookup.owner,lookup.namespace,lookup.name,1,0
 FROM cr_binding_names name LEFT JOIN cr_binding_masks mask ON mask.owner=name.owner
 CROSS JOIN cr_binding_imports blocker ON blocker.owner=COALESCE(mask.base_owner,name.owner)
 AND blocker.is_glob=0 AND blocker.bound_name=name.name
 CROSS JOIN cr_binding_lookups lookup ON lookup.blob_id=blocker.blob_id AND lookup.import_ordinal=blocker.import_ordinal
 AND lookup.module_path=blocker.module_path AND (lookup.position<blocker.segments OR lookup.namespace=name.namespace)
 WHERE (mask.owner IS NULL OR blocker.blob_id<>mask.blob_id OR blocker.import_ordinal<>mask.import_ordinal OR blocker.module_path<>mask.module_path)
 AND (EXISTS(SELECT 1 FROM cr_binding_globs glob WHERE glob.owner=name.owner)
 OR (name.namespace='type' AND EXISTS(SELECT 1 FROM cr_dependencies dependency WHERE dependency.extern_name=name.name)))
 AND NOT EXISTS(SELECT 1 FROM cr_binding_targets strong WHERE strong.owner=name.owner AND strong.namespace=name.namespace
 AND strong.name=name.name AND strong.origin IN ('declaration','reexport'))
 UNION SELECT destination.owner,name.namespace,name.name,lookup.owner,'type',lookup.name,1,0
 FROM cr_binding_destinations destination CROSS JOIN cr_binding_imports source
 ON source.blob_id=destination.blob_id AND source.import_ordinal=destination.import_ordinal AND source.module_path=destination.module_path
 CROSS JOIN cr_binding_names name ON name.owner=destination.owner AND (source.is_glob=1 OR source.bound_name=name.name)
 CROSS JOIN cr_binding_lookups lookup ON lookup.blob_id=source.blob_id AND lookup.import_ordinal=source.import_ordinal
 AND lookup.module_path=source.module_path AND lookup.position=0 AND lookup.namespace='type'
 WHERE (lookup.name IN ('std','core','alloc') OR EXISTS(SELECT 1 FROM cr_dependencies dependency
 WHERE dependency.extern_name=lookup.name AND dependency.dependency_crate_key IS NULL))
 AND (source.segments>0 OR name.namespace='type')
 AND NOT (destination.owner=lookup.owner AND name.namespace='type' AND name.name=lookup.name)
 AND NOT (source.is_glob=1 AND name.namespace='type' AND EXISTS(SELECT 1 FROM cr_binding_lookups root
 CROSS JOIN cr_binding_destinations importing ON importing.blob_id=root.blob_id
 AND importing.import_ordinal=root.import_ordinal AND importing.module_path=root.module_path
 WHERE root.owner=destination.owner AND root.position=0 AND root.namespace='type' AND root.name=name.name
 AND (root.name IN ('std','core','alloc') OR EXISTS(SELECT 1 FROM cr_dependencies dependency
 WHERE dependency.extern_name=root.name AND dependency.dependency_crate_key IS NULL))))
 AND NOT EXISTS(SELECT 1 FROM cr_binding_targets strong WHERE strong.owner=name.owner
 AND strong.namespace=name.namespace AND strong.name=name.name AND (strong.origin='declaration' OR (source.is_glob=1 AND strong.origin='reexport')))
 UNION SELECT name.owner,name.namespace,name.name,owner.parent_owner,name.namespace,name.name,0,1
 FROM cr_binding_names name CROSS JOIN cr_binding_owners owner ON owner.owner=name.owner
 WHERE owner.parent_owner IS NOT NULL AND NOT EXISTS(SELECT 1 FROM cr_binding_targets own WHERE own.owner=name.owner
 AND own.namespace=name.namespace AND own.name=name.name))
 SELECT source.node,target.node,dependency.negative,dependency.propagates_ambiguity FROM dependencies dependency
 CROSS JOIN cr_binding_nodes source ON source.owner=dependency.owner AND source.namespace=dependency.namespace AND source.name=dependency.name
 CROSS JOIN cr_binding_nodes target ON target.owner=dependency.target_owner AND target.namespace=dependency.target_namespace AND target.name=dependency.target_name
 WHERE true ON CONFLICT(source,target,negative) DO UPDATE
 SET propagates_ambiguity=MAX(cr_binding_edges.propagates_ambiguity,excluded.propagates_ambiguity)";

pub(super) const CLEAR_EDGES_SQL: &str = "DELETE FROM cr_binding_edges";
pub(super) const CLEAR_COMPONENTS_SQL: &str = "DELETE FROM cr_binding_components";
pub(super) const INSERT_COMPONENT_SQL: &str = "INSERT INTO cr_binding_components VALUES(?1,?2)";

pub(super) const SOURCE_OPEN_SQL: &str = "INSERT OR IGNORE INTO cr_binding_open_sources
 SELECT source.blob_id,source.import_ordinal,source.module_path,namespace.value
 FROM cr_binding_imports source CROSS JOIN cr_binding_lookups lookup
 ON lookup.blob_id=source.blob_id AND lookup.import_ordinal=source.import_ordinal
 AND lookup.module_path=source.module_path AND lookup.position=0 AND lookup.namespace='type'
 CROSS JOIN cr_binding_complete done ON done.owner=lookup.owner AND done.namespace='type' AND done.name=lookup.name
 CROSS JOIN json_each('[\"type\",\"value\",\"macro\"]') namespace
 WHERE (source.segments>0 OR namespace.value='type')
 AND (lookup.name IN ('std','core','alloc') OR EXISTS(SELECT 1 FROM cr_dependencies dependency
 WHERE dependency.extern_name=lookup.name AND dependency.dependency_crate_key IS NULL))
 AND NOT EXISTS(SELECT 1 FROM cr_binding_targets strong WHERE strong.owner=lookup.owner
 AND strong.namespace='type' AND strong.name=lookup.name AND strong.origin IN ('declaration','reexport'))";

// An opaque known macro can mention a binding the crate's glob currently
// supplies. Its structured transcriber identifiers are a conservative name
// inventory, not replayed declarations. Explicit item/named bindings still win.
//
// The rows are monotone, so the absence of a named binding must be read from
// settled facts. Run it only once propagation has quiesced, never inside the
// propagation passes: IMPORT_COMPLETE_SQL can mark a named import complete in
// the pass that writes its terminal path, before LOOKUPS_SQL has materialized
// that path's terminal lookups and before PRESENT_SQL has seen the target
// they read. Read mid-pass, `use crate::{Adaptor, TestOutput};` in a module
// with an open macro inventory looked complete with nothing present, and the
// explicitly imported type alias was opened (#6136). At quiescence every
// admitted target has passed through PRESENT_SQL, and COMPLETE_SQL and
// PENDING_SQL, the only readers of open names, run after it.
pub(super) const MACRO_OPEN_NAMES_SQL: &str = "INSERT OR IGNORE INTO cr_binding_open_names(owner,namespace,name,inventory)
 SELECT name.owner,name.namespace,name.name,
 CASE WHEN owner.crate_key=(SELECT crate_key FROM cr_identity) THEN gap.detail ELSE 'null' END
 FROM cr_binding_names name CROSS JOIN cr_binding_owners owner ON owner.owner=name.owner
 CROSS JOIN cr_gaps gap ON gap.gap_kind='open_export_inventory' AND gap.subject=owner.module_path
 CROSS JOIN source_rust_macro_definitions definition ON definition.blob_id=json_extract(gap.detail,'$.member_blob')
 CROSS JOIN source_declaration_units mapping ON mapping.blob_id=definition.blob_id AND mapping.declaration_id=definition.declaration_id
 CROSS JOIN code_units unit ON unit.blob_id=mapping.blob_id AND unit.unit_key=mapping.unit_key AND unit.identifier=json_extract(gap.detail,'$.macro')
 CROSS JOIN source_rust_macro_arms arm ON arm.blob_id=definition.blob_id AND arm.declaration_id=definition.declaration_id
 CROSS JOIN json_each(arm.transcriber_identifiers) identifier ON identifier.value=name.name
 WHERE owner.blob_id=0 AND owner.binder_scope=0
 AND json_extract(gap.detail,'$.reason')='UnsupportedMacroGeneratedModule'
 AND NOT EXISTS(SELECT 1 FROM cr_binding_targets item WHERE item.owner=name.owner AND item.namespace=name.namespace
 AND item.name=name.name AND item.origin IN ('declaration','reexport'))
 AND NOT EXISTS(SELECT 1 FROM cr_binding_imports named WHERE named.owner=name.owner AND named.is_glob=0 AND named.bound_name=name.name
 AND (NOT EXISTS(SELECT 1 FROM cr_binding_import_complete done WHERE done.blob_id=named.blob_id AND done.import_ordinal=named.import_ordinal
 AND done.module_path=named.module_path AND done.namespace=name.namespace)
 OR EXISTS(SELECT 1 FROM cr_binding_import_present present WHERE present.blob_id=named.blob_id AND present.import_ordinal=named.import_ordinal
 AND present.module_path=named.module_path AND present.namespace=name.namespace)))";
