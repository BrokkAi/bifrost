//! Own bindings and their coverage, with logical source identities at publication.
//! Lexical inheritance, selected content and requester access remain query work.
use super::*;

pub(super) const SCHEMA_SQL: &str = "
CREATE TEMP TABLE IF NOT EXISTS cr_authority_source_paths(
 crate_key BLOB NOT NULL,blob_id INTEGER NOT NULL,rel_path TEXT NOT NULL,
 PRIMARY KEY(crate_key,blob_id)) WITHOUT ROWID;
CREATE TEMP TABLE IF NOT EXISTS cr_authority_local_seeds AS SELECT * FROM cr_binding_targets WHERE 0;
CREATE TEMP TABLE IF NOT EXISTS cr_authority_blockers(
 owner INTEGER NOT NULL,namespace TEXT NOT NULL,name TEXT NOT NULL,
 reason TEXT NOT NULL,boundary TEXT NOT NULL,evidence_crate_key BLOB NOT NULL,evidence_module_path TEXT NOT NULL,
 evidence_rel_path TEXT NOT NULL,evidence_kind TEXT NOT NULL,evidence_key INTEGER NOT NULL,owner_gap INTEGER NOT NULL,
 PRIMARY KEY(owner,namespace,name,reason,boundary,evidence_crate_key,evidence_module_path,evidence_rel_path,evidence_kind,evidence_key,owner_gap)
) WITHOUT ROWID;
CREATE TEMP VIEW IF NOT EXISTS cr_authority_owner_keys AS
 SELECT owner.owner,owner.module_path,
 CASE WHEN owner.blob_id=0 THEN 'module' ELSE 'local' END AS kind,
 CASE WHEN owner.blob_id=0 THEN '' ELSE member.rel_path END AS rel_path,
 CASE WHEN owner.blob_id=0 THEN X'' ELSE scope.identity_digest END AS scope_identity,
 NULLIF(owner.blob_id,0) AS blob_id,
 CASE WHEN owner.blob_id<>0 THEN owner.binder_scope END AS native_scope,
 owner.parent_owner
 FROM cr_binding_owners owner CROSS JOIN cr_identity identity ON identity.crate_key=owner.crate_key
 LEFT JOIN cr_members member ON owner.blob_id<>0 AND member.blob_id=owner.blob_id
 AND member.module_path=owner.module_path
 LEFT JOIN resolution_node_catalog scope ON scope.blob_id=owner.blob_id AND scope.source_scope=owner.binder_scope
 WHERE owner.binder_scope>=0 AND (owner.blob_id=0 OR scope.kind=1)
 AND NOT EXISTS(SELECT 1 FROM cr_binding_masks mask WHERE mask.owner=owner.owner);
";

// Unknown sources, rather than the coarse owners.open bit, decide universal
// coverage. Carry the original owner-wide evidence through glob chains and
// SCCs: unlisted names have no binding nodes, so the derivation cannot carry
// it. Per-name evidence comes only from cr_gaps, where the derivation already
// carried it along the binding edges that can actually import the name.
// owner_gap marks the owner's own unscoped gaps. They can add a binding of
// equal rank to any name, so they also void that namespace's certificates;
// a declaration or named import shadows what an open glob source adds.
pub(super) const BLOCKERS_SQL: &str = "INSERT OR IGNORE INTO cr_authority_blockers
 WITH RECURSIVE inputs(owner,namespace,name,reason,boundary,evidence_crate_key,evidence_module_path,
 evidence_rel_path,evidence_kind,evidence_key,owner_gap) AS (
 SELECT owner.owner,COALESCE(json_extract(gap.detail,'$.namespace'),namespace.value),
 CASE WHEN gap.subject=owner.module_path THEN '' ELSE substr(gap.subject,length(owner.module_path)+3) END,
 COALESCE(json_extract(gap.detail,'$.reason'),gap.gap_kind),
 COALESCE(json_extract(gap.detail,'$.boundary'),'workspace_local'),owner.crate_key,owner.module_path,
 COALESCE(member.rel_path,''),
 CASE WHEN json_extract(gap.detail,'$.declaration_id') IS NOT NULL THEN 'declaration'
 WHEN json_extract(gap.detail,'$.invocation_occurrence') IS NOT NULL THEN 'macro'
 WHEN json_extract(gap.detail,'$.import_ordinal') IS NOT NULL THEN 'import' ELSE 'owner' END,
 COALESCE(json_extract(gap.detail,'$.declaration_id'),json_extract(gap.detail,'$.invocation_occurrence'),
 json_extract(gap.detail,'$.import_ordinal'),0),
 gap.subject=owner.module_path AND (owner.blob_id<>0 OR json_type(gap.detail,'$.binder_scope') IS NULL)
 FROM cr_binding_owners owner CROSS JOIN cr_gaps gap
 ON gap.subject=owner.module_path OR substr(gap.subject,1,length(owner.module_path)+2)=owner.module_path || '::'
 CROSS JOIN cr_identity identity ON identity.crate_key=owner.crate_key
 CROSS JOIN json_each('[\"type\",\"value\",\"macro\"]') namespace
 LEFT JOIN cr_members member ON member.module_path=owner.module_path
 AND member.blob_id=json_extract(gap.detail,'$.member_blob')
 WHERE gap.gap_kind IN ('open_export_inventory','unknown_activation','unresolved_visibility','unplaced_module','duplicate_placement')
 AND (json_extract(gap.detail,'$.binder_scope') IS NULL
 OR (json_extract(gap.detail,'$.binder_scope')=owner.binder_scope AND json_extract(gap.detail,'$.member_blob')=owner.blob_id))
 AND (owner.blob_id=0 OR json_extract(gap.detail,'$.member_blob')=owner.blob_id)
 AND (gap.subject=owner.module_path OR EXISTS(SELECT 1 FROM cr_binding_names name
 WHERE name.owner=owner.owner AND gap.subject=owner.module_path || '::' || name.name))
 UNION
 SELECT source.owner,namespace.value,'','OpenBoundary',
 CASE WHEN opened.namespace IS NULL THEN 'workspace_local' ELSE 'external_declared_unindexed' END,
 (SELECT crate_key FROM cr_identity),source.module_path,member.rel_path,'import',source.import_ordinal,0
 FROM cr_binding_imports source CROSS JOIN json_each('[\"type\",\"value\",\"macro\"]') namespace
 CROSS JOIN cr_members member ON member.blob_id=source.blob_id AND member.module_path=source.module_path
 LEFT JOIN cr_binding_open_sources opened ON opened.blob_id=source.blob_id
 AND opened.import_ordinal=source.import_ordinal AND opened.module_path=source.module_path AND opened.namespace=namespace.value
 WHERE source.is_glob=1 AND NOT EXISTS(SELECT 1 FROM cr_binding_import_complete complete
 WHERE complete.blob_id=source.blob_id AND complete.import_ordinal=source.import_ordinal
 AND complete.module_path=source.module_path AND complete.namespace=namespace.value)
 UNION
 SELECT owner.owner,blocker.namespace,blocker.name,blocker.reason,blocker.boundary,
 blocker.evidence_crate_key,blocker.evidence_module_path,blocker.evidence_rel_path,blocker.evidence_kind,blocker.evidence_key,0
 FROM cr_binding_owners owner CROSS JOIN cr_foreign foreign_owner ON foreign_owner.crate_key=owner.crate_key
 CROSS JOIN rust_crate_binding_owners published ON published.topology_id=foreign_owner.topology_id
 AND published.module_path=owner.module_path AND published.kind='module'
 CROSS JOIN rust_crate_binding_blockers blocker ON blocker.owner_id=published.owner_id AND blocker.name=''
 WHERE owner.blob_id=0 AND owner.binder_scope=0
 UNION
 SELECT glob.owner,input.namespace,input.name,input.reason,input.boundary,
 input.evidence_crate_key,input.evidence_module_path,input.evidence_rel_path,input.evidence_kind,input.evidence_key,0
 FROM inputs input CROSS JOIN cr_binding_globs glob ON glob.target_owner=input.owner WHERE input.name=''
 ) SELECT * FROM inputs";

pub(super) const OWNERS_SQL: &str = "SELECT DISTINCT owner.module_path,owner.kind,owner.rel_path,
 owner.scope_identity,owner.blob_id,owner.native_scope,
 CASE WHEN owner.kind='local' THEN parent.module_path ELSE COALESCE(member.parent_module_path,enum.module_path) END,
 CASE WHEN owner.kind='local' THEN COALESCE(parent.rel_path,'') ELSE '' END,
 CASE WHEN owner.kind='local' THEN COALESCE(parent.scope_identity,X'') ELSE X'' END,
 NOT EXISTS(SELECT 1 FROM cr_authority_blockers blocker WHERE blocker.owner=owner.owner AND blocker.name='')
 FROM cr_authority_owner_keys owner
 LEFT JOIN cr_authority_owner_keys parent ON parent.owner=owner.parent_owner
 LEFT JOIN cr_members member ON owner.kind='module' AND member.module_path=owner.module_path
 LEFT JOIN cr_enums enum ON owner.kind='module' AND enum.container_path=owner.module_path
 ORDER BY 1,3,4";

pub(super) const NAMES_SQL: &str =
    "SELECT DISTINCT owner.module_path,owner.rel_path,owner.scope_identity,
 name.namespace,name.name,EXISTS(SELECT 1 FROM cr_binding_complete complete
 WHERE complete.owner=name.owner AND complete.namespace=name.namespace AND complete.name=name.name)
 AND NOT EXISTS(SELECT 1 FROM cr_authority_blockers blocker WHERE blocker.owner=name.owner
 AND blocker.namespace=name.namespace AND blocker.owner_gap)
 FROM cr_authority_owner_keys owner CROSS JOIN cr_binding_names name ON name.owner=owner.owner
 WHERE name.name<>'self' ORDER BY 1,2,3,4,5";

pub(super) const REASONS_SQL: &str = "SELECT DISTINCT owner.module_path,owner.rel_path,owner.scope_identity,
 blocker.namespace,blocker.name,blocker.reason,blocker.boundary,blocker.evidence_crate_key,blocker.evidence_module_path,
 blocker.evidence_rel_path,blocker.evidence_kind,blocker.evidence_key
 FROM cr_authority_owner_keys owner CROSS JOIN cr_authority_blockers blocker ON blocker.owner=owner.owner
 ORDER BY 1,2,3,4,5,6,7,8,9,10,11,12";

pub(super) const OWNERS_INSERT_SQL: &str = "INSERT INTO rust_crate_binding_owners(
 topology_id,module_path,kind,rel_path,scope_identity,blob_id,native_scope,closed)
 VALUES(?1,?2,?3,?4,?5,?6,?7,?11)";

pub(super) const PARENTS_UPDATE_SQL: &str = "UPDATE rust_crate_binding_owners SET parent_owner_id=(
 SELECT parent.owner_id FROM rust_crate_binding_owners parent WHERE parent.topology_id=?1
 AND parent.module_path=?8 AND parent.rel_path=?9 AND parent.scope_identity=?10)
 WHERE topology_id=?1 AND module_path=?2 AND rel_path=?4 AND scope_identity=?5";

pub(super) const NAMES_INSERT_SQL: &str = "INSERT INTO rust_crate_binding_names
 SELECT owner_id,?5,?6,?7 FROM rust_crate_binding_owners
 WHERE topology_id=?1 AND module_path=?2 AND rel_path=?3 AND scope_identity=?4";

pub(super) const REASONS_INSERT_SQL: &str = "INSERT INTO rust_crate_binding_blockers
 SELECT owner_id,?5,?6,?7,?8,?9,?10,?11,?12,?13 FROM rust_crate_binding_owners
 WHERE topology_id=?1 AND module_path=?2 AND rel_path=?3 AND scope_identity=?4";

// Declaration witnesses are local seeds, never inherited copies. Imported
// witnesses come from the same admitted first-hop relation summaries consume.
pub(super) static ALTERNATIVES_SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!("WITH macro_items AS (
 SELECT identity.crate_key,item.* FROM cr_macro_items item CROSS JOIN cr_identity identity
 UNION ALL
 SELECT foreign_owner.crate_key,item.module_path,item.namespace,item.name,item.visibility,
 item.restricted_module_path,item.blob_id,item.invocation_occurrence_id,item.declaration_id,item.module_item
 FROM cr_foreign foreign_owner CROSS JOIN rust_crate_macro_items item ON item.topology_id=foreign_owner.topology_id
 ), witnesses AS (
 SELECT owner.owner,target.namespace,target.name,target.target_crate_key,
 target.target_module_path,target.target_name,target.declaration_blob_id,target.declaration_site,
 'declaration' AS origin,target.visibility,target.restricted_module_path,
 NULL AS provider_crate_key,NULL AS provider_module_path,NULL AS provider_rel_path,
 NULL AS provider_scope_identity,NULL AS glob_visibility,NULL AS glob_restricted_module_path
 FROM cr_binding_exact_targets target CROSS JOIN cr_binding_owners owner ON owner.owner=target.owner
 CROSS JOIN cr_identity identity ON identity.crate_key=owner.crate_key
 WHERE target.origin='declaration' AND (owner.blob_id=0 OR EXISTS(
 SELECT 1 FROM cr_authority_local_seeds seed WHERE seed.owner=owner.owner
 AND seed.namespace=target.namespace AND seed.name=target.name
 AND seed.declaration_blob_id=target.declaration_blob_id AND seed.declaration_site=target.declaration_site))
 UNION
 SELECT source.owner,edge.namespace,edge.name,edge.target_crate_key,edge.target_module_path,edge.target_name,
 target.declaration_blob_id,target.declaration_site,CASE source.is_glob WHEN 1 THEN 'glob' ELSE 'named_import' END,
 target.visibility,target.restricted_module_path,
 CASE WHEN source.is_glob=1 THEN edge.provider_crate_key END,
 CASE WHEN source.is_glob=1 THEN edge.provider_module_path END,
 CASE WHEN source.is_glob=1 THEN COALESCE(provider_source.rel_path,'') END,
 CASE WHEN source.is_glob=1 THEN COALESCE(provider_scope.identity_digest,X'') END,
 CASE WHEN source.is_glob=1 THEN source.visibility END,
 CASE WHEN source.is_glob=1 THEN source.restricted_module_path END
 FROM ({BINDING_PROVENANCE_SELECT_SQL}) edge
 CROSS JOIN cr_binding_imports source ON source.blob_id=edge.blob_id
 AND source.import_ordinal=edge.import_ordinal AND source.module_path=edge.module_path
 CROSS JOIN cr_binding_exact_targets target ON target.owner=source.owner
 AND target.namespace=edge.namespace AND target.name=edge.name
 AND target.target_crate_key=edge.target_crate_key AND target.target_module_path=edge.target_module_path
 AND target.target_name=edge.target_name
 LEFT JOIN cr_members provider_source ON edge.provider_blob_id<>0
 AND provider_source.blob_id=edge.provider_blob_id AND provider_source.module_path=edge.provider_module_path
 LEFT JOIN resolution_node_catalog provider_scope ON provider_scope.blob_id=edge.provider_blob_id
 AND provider_scope.source_scope=edge.provider_binder_scope
 UNION
 -- A named import's certain target is already decided per namespace. Its
 -- first hop can be a synthetic extern-prelude read (`use dep as alias;`)
 -- that has no provenance edge, so the witness cannot depend on one.
 SELECT owner.owner,target.namespace,target.name,target.target_crate_key,
 target.target_module_path,target.target_name,target.declaration_blob_id,target.declaration_site,
 'named_import',target.visibility,target.restricted_module_path,NULL,NULL,NULL,NULL,NULL,NULL
 FROM cr_binding_exact_targets target CROSS JOIN cr_binding_owners owner ON owner.owner=target.owner
 CROSS JOIN cr_identity identity ON identity.crate_key=owner.crate_key
 WHERE target.origin='reexport'
 )
 SELECT DISTINCT owner.module_path,owner.rel_path,owner.scope_identity,
 witness.namespace,witness.name,witness.target_crate_key,witness.target_module_path,witness.target_name,
 container.container_path,witness.origin,
 CASE WHEN witness.declaration_blob_id<>0 THEN witness.declaration_blob_id ELSE item.blob_id END,
 CASE WHEN witness.declaration_blob_id<>0 THEN witness.declaration_site END,
 item.declaration_id,witness.visibility,witness.restricted_module_path,
 witness.provider_crate_key,witness.provider_module_path,witness.provider_rel_path,witness.provider_scope_identity,
 witness.glob_visibility,witness.glob_restricted_module_path,
 COALESCE(source_path.rel_path,''),
 COALESCE(declaration_identity.identity_digest,shared_identity.identity_digest),generated_unit.exact_fqn
 FROM witnesses witness CROSS JOIN cr_authority_owner_keys owner ON owner.owner=witness.owner
 LEFT JOIN cr_containers_all container ON container.crate_key=witness.target_crate_key
 AND container.container_path=CASE WHEN witness.target_name='self' THEN witness.target_module_path
 ELSE witness.target_module_path || '::' || witness.target_name END
 LEFT JOIN macro_items item ON witness.declaration_blob_id=0
 AND witness.target_crate_key=item.crate_key
 AND item.module_path=witness.target_module_path AND item.namespace=witness.namespace AND item.name=witness.target_name
 LEFT JOIN resolution_semantic_sites declaration_site ON declaration_site.blob_id=witness.declaration_blob_id
 AND declaration_site.source_site=witness.declaration_site AND declaration_site.semantic_role='definition'
 LEFT JOIN resolution_semantic_catalog declaration_identity ON declaration_identity.blob_id=declaration_site.blob_id
 AND declaration_identity.local_key=declaration_site.semantic_key
 LEFT JOIN resolution_identities shared_identity ON shared_identity.id=declaration_identity.shared_identity
 LEFT JOIN cr_authority_source_paths source_path ON source_path.crate_key=witness.target_crate_key
 AND source_path.blob_id=COALESCE(NULLIF(witness.declaration_blob_id,0),item.blob_id)
 LEFT JOIN source_declaration_units generated_mapping ON generated_mapping.blob_id=item.blob_id AND generated_mapping.declaration_id=item.declaration_id
 LEFT JOIN code_units generated_unit ON generated_unit.blob_id=generated_mapping.blob_id AND generated_unit.unit_key=generated_mapping.unit_key
 WHERE witness.name<>'self' ORDER BY 1,2,3,4,5,6,7,8,9,10,14,15,16,17,18,19,20,21,22,23,24")
});

pub(super) const ALTERNATIVES_INSERT_SQL: &str = "INSERT INTO rust_crate_binding_alternatives(
 owner_id,namespace,name,target_crate_key,target_module_path,target_name,target_container_path,origin,
 declaration_blob_id,declaration_site,generated_declaration_id,visibility,restricted_module_path,
 provider_crate_key,provider_module_path,provider_rel_path,provider_scope_identity,glob_visibility,glob_restricted_module_path)
 SELECT owner_id,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22
 FROM rust_crate_binding_owners WHERE topology_id=?1 AND module_path=?2 AND rel_path=?3 AND scope_identity=?4";

// Full rows are the result of this single derivation query, not a retained
// workspace index. Logical hashing excludes storage coordinates, not facts.
pub(super) fn hash_rows(
    digest: &mut Sha256,
    rows: &[Vec<Value>],
    family: &str,
    physical_columns: &[usize],
) {
    hash_cell(digest, family.as_bytes());
    for row in rows {
        for (column, value) in row.iter().enumerate() {
            if physical_columns.contains(&column) {
                continue;
            }
            match value {
                Value::Null => hash_cell(digest, b"null"),
                Value::Text(value) => hash_cell(digest, value.as_bytes()),
                Value::Blob(value) => hash_cell(digest, value),
                Value::Integer(value) => hash_cell(digest, &value.to_be_bytes()),
                Value::Real(_) => {
                    unreachable!("binding authority contains no floating point values")
                }
            }
        }
    }
}

// A declaration is owned by the scope head of its direct definition path.
// This reads native structure, not source extents guessed from spelling.
pub(super) const LOCAL_DECLARATIONS_SQL: &str = "INSERT OR IGNORE INTO cr_authority_local_seeds
 SELECT DISTINCT owner.owner,cr_authority_namespace(name.namespace),
 name.spelling,owner.crate_key,owner.module_path,name.spelling,
 authority.blob_id,authority.source_site,'declaration','private',NULL
 FROM cr_binding_owners owner CROSS JOIN cr_identity identity ON identity.crate_key=owner.crate_key
 CROSS JOIN resolution_node_catalog scope ON scope.blob_id=owner.blob_id AND scope.source_scope=owner.binder_scope
 CROSS JOIN resolution_paths path INDEXED BY resolution_paths_forward
 ON path.blob_id=scope.blob_id AND path.start_node=scope.local_key
 CROSS JOIN resolution_identities name ON name.id=path.start_lead_identity
 CROSS JOIN resolution_node_catalog endpoint ON endpoint.blob_id=path.blob_id AND endpoint.local_key=path.end_node
 CROSS JOIN resolution_rust_declaration_authorities authority
 ON authority.blob_id=endpoint.blob_id AND authority.semantic_key=endpoint.semantic_local_key
 WHERE owner.blob_id<>0 AND owner.binder_scope>=0 AND scope.kind=1
 AND path.root_terminal IS NULL AND path.end_lead_identity IS NULL AND path.end_lead_local IS NULL
 AND cr_authority_cfg(json(authority.cfg_condition),?1)=1";

pub(super) const LOCAL_OWNERS_SQL: &str = "INSERT OR IGNORE INTO cr_binding_owners(crate_key,module_path,blob_id,binder_scope)
 SELECT identity.crate_key,member.module_path,scope.blob_id,scope.source_scope
 FROM cr_member_blobs selected CROSS JOIN cr_identity identity
 CROSS JOIN resolution_rust_declaration_authorities authority ON authority.blob_id=selected.blob_id
 CROSS JOIN source_declarations declaration ON declaration.blob_id=authority.blob_id AND declaration.declaration_id=authority.declaration
 CROSS JOIN resolution_node_catalog endpoint ON endpoint.blob_id=authority.blob_id AND endpoint.semantic_local_key=authority.semantic_key
 CROSS JOIN resolution_paths path ON path.blob_id=endpoint.blob_id AND path.end_node=endpoint.local_key
 CROSS JOIN resolution_node_catalog scope ON scope.blob_id=path.blob_id AND scope.local_key=path.start_node AND scope.kind=1
 CROSS JOIN cr_members member ON member.blob_id=scope.blob_id
 AND declaration.start_byte>=member.start_byte AND declaration.end_byte<=member.end_byte
 CROSS JOIN source_rust_module_scopes module ON module.blob_id=member.blob_id AND module.ordinal=member.scope_ordinal
 WHERE scope.source_scope IS NOT NULL AND scope.source_scope<>module.resolution_scope
 AND path.start_lead_identity IS NOT NULL AND path.root_terminal IS NULL
 AND NOT EXISTS(SELECT 1 FROM resolution_member_scope_properties body WHERE body.blob_id=scope.blob_id AND body.scope_head_node_key=scope.local_key)
 AND NOT EXISTS(SELECT 1 FROM cr_scopes inner_module WHERE inner_module.blob_id=member.blob_id
 AND inner_module.scope_ordinal<>member.scope_ordinal AND inner_module.start_byte>=member.start_byte
 AND inner_module.end_byte<=member.end_byte AND declaration.start_byte>=inner_module.start_byte
 AND declaration.end_byte<=inner_module.end_byte)";

pub(super) const LOCAL_PARENTS_SQL: &str = "WITH RECURSIVE ancestors(owner,blob_id,node) AS (
 SELECT owner.owner,scope.blob_id,path.end_node
 FROM cr_binding_owners owner
 CROSS JOIN resolution_node_catalog scope ON scope.blob_id=owner.blob_id AND scope.source_scope=owner.binder_scope
 CROSS JOIN resolution_paths path INDEXED BY resolution_paths_forward ON path.blob_id=scope.blob_id AND path.start_node=scope.local_key
 WHERE owner.blob_id<>0 AND path.start_lead_identity IS NULL AND path.start_lead_local IS NULL
 AND path.end_lead_identity IS NULL AND path.end_lead_local IS NULL AND path.end_node>=0
 UNION
 SELECT ancestor.owner,ancestor.blob_id,path.end_node FROM ancestors ancestor
 CROSS JOIN resolution_node_catalog node ON node.blob_id=ancestor.blob_id AND node.local_key=ancestor.node
 CROSS JOIN resolution_paths path INDEXED BY resolution_paths_forward ON path.blob_id=node.blob_id AND path.start_node=node.local_key
 WHERE path.start_lead_identity IS NULL AND path.start_lead_local IS NULL
 AND path.end_lead_identity IS NULL AND path.end_lead_local IS NULL AND path.end_node>=0
 AND NOT EXISTS(SELECT 1 FROM cr_binding_owners matched WHERE matched.blob_id=node.blob_id AND matched.binder_scope=node.source_scope)
 ) UPDATE cr_binding_owners AS owner SET parent_owner=COALESCE((
 SELECT parent.owner FROM ancestors ancestor
 CROSS JOIN resolution_node_catalog node ON node.blob_id=ancestor.blob_id AND node.local_key=ancestor.node
 CROSS JOIN cr_binding_owners parent ON parent.blob_id=node.blob_id AND parent.binder_scope=node.source_scope
 AND parent.crate_key=owner.crate_key AND parent.module_path=owner.module_path
 WHERE ancestor.owner=owner.owner),parent_owner) WHERE owner.blob_id<>0";
