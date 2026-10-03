//! One fragment's lexical projection. Preparation is discarded after its
//! transaction; readers seek the resulting host aggregate in SQLite.

use super::codec;
use crate::CancellationToken;
use crate::analyzer::resolution::{
    BindingNodeId, BindingNodeKind, EndpointSignature, LoweredResolutionFragment,
    LoweringCoverageFrontier, SelectedResolutionMountOrdinal, SemanticId,
};
use crate::analyzer::store::resolution_prepare::resolution_rows::{self, RootKeyBuilder};
use crate::analyzer::store::{Result, StoreError};
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use rusqlite::{Connection, params};
use serde_json::{Value, json};

/// One fragment query's SQL parameter rows, never retained as read authority.
pub(super) struct PreparedStageLexical {
    fragment: crate::analyzer::resolution::BindingFragmentId,
    language: crate::analyzer::Language,
    nodes: Vec<Value>,
    paths: Vec<Value>,
    semantics: Vec<Value>,
    gaps: Vec<Value>,
}

pub(in crate::analyzer::store) fn semantic_cells(
    semantic: SemanticId,
) -> (Option<i64>, Option<i64>) {
    let encoded = codec::encode_semantic(semantic);
    if encoded < 0 {
        (None, Some(-encoded))
    } else {
        (Some(encoded), None)
    }
}

/// Decode an actual ordinary catalog payload with its selected owner and
/// request shared-name aliases. NULL kind remains catalog-only authority.
pub(in crate::analyzer::store) fn decode_ordinary_node_kind(
    host: u32,
    kind: Option<i64>,
    semantic_local: Option<u32>,
    semantic_shared: Option<i64>,
    target_local: Option<u32>,
    target_boundary: Option<i64>,
    names: &dyn crate::analyzer::resolution::SharedNameInterner,
) -> Option<BindingNodeKind> {
    use crate::analyzer::resolution::SharedNameId;
    let kind = kind?;
    let semantic = match (semantic_local, semantic_shared) {
        (Some(key), None) => Some(SemanticId::local(host, key)),
        (None, Some(shared)) => Some(SemanticId::shared_name(
            names.from_persisted(SharedNameId::interned(shared)),
        )),
        (None, None) => None,
        pair => panic!("ordinary node has invalid semantic pair: {pair:?}"),
    };
    let target = match (target_local, target_boundary) {
        (Some(key), None) => Some(BindingNodeId::local(host, key)),
        (None, Some(0)) => Some(BindingNodeId::universal_root()),
        (None, None) => None,
        pair => panic!("ordinary node has invalid target pair: {pair:?}"),
    };
    Some(codec::decode_node_kind(kind, semantic, target))
}

fn endpoint_lead(endpoint: &EndpointSignature) -> (Option<i64>, Option<i64>, bool) {
    endpoint
        .symbols()
        .fixed()
        .first()
        .map_or((None, None, false), |symbol| {
            let (key, shared) = semantic_cells(symbol.symbol());
            (key, shared, symbol.scopes().is_some())
        })
}

fn node_cells(node: BindingNodeId, kind: BindingNodeKind) -> Value {
    let (tag, semantic, target) = match kind {
        BindingNodeKind::Root => (0, None, None),
        BindingNodeKind::Scope => (1, None, None),
        BindingNodeKind::PushSymbol(semantic) => (2, Some(semantic), None),
        BindingNodeKind::PopSymbol(semantic) => (3, Some(semantic), None),
        BindingNodeKind::PushScopedSymbol(semantic) => (4, Some(semantic), None),
        BindingNodeKind::PopScopedSymbol(semantic) => (5, Some(semantic), None),
        BindingNodeKind::DropScopes => (6, None, None),
        BindingNodeKind::JumpToScope(target) => (7, None, Some(target)),
        BindingNodeKind::Reference(semantic) => (8, Some(semantic), None),
        BindingNodeKind::Definition(semantic) => (9, Some(semantic), None),
    };
    let (key, shared) = semantic.map_or((None, None), semantic_cells);
    json!([
        codec::encode_node(node),
        tag,
        key,
        shared,
        target.map(codec::encode_node)
    ])
}

pub(super) fn prepare_lexical_fragment(
    fragment: &LoweredResolutionFragment,
    cancellation: &CancellationToken,
) -> Option<PreparedStageLexical> {
    let mut result = PreparedStageLexical {
        fragment: fragment.fragment(),
        language: fragment.language(),
        nodes: Vec::new(),
        paths: Vec::new(),
        semantics: Vec::new(),
        gaps: Vec::new(),
    };
    for &(node, kind) in fragment.nodes() {
        if cancellation.is_cancelled() {
            return None;
        }
        result.nodes.push(node_cells(node, kind));
    }
    for (id, path) in fragment.paths() {
        if cancellation.is_cancelled() {
            return None;
        }
        let start = endpoint_lead(path.start());
        let end = endpoint_lead(path.end());
        let root = path.end().node() == BindingNodeId::universal_root();
        let (fixed, tail) = if root {
            let mut key = RootKeyBuilder::default();
            for symbol in path.end().symbols().fixed() {
                if cancellation.is_cancelled() {
                    return None;
                }
                let (runtime, shared) = semantic_cells(symbol.symbol());
                key.push(runtime, shared, symbol.scopes().is_some());
            }
            (
                Some(key.finish().0),
                Some(path.end().symbols().tail().is_some()),
            )
        } else {
            (None, None)
        };
        let terminal = if root && path.end().symbols().fixed().len() >= 3 {
            path.end()
                .symbols()
                .fixed()
                .last()
                .expect("three fixed cells have a last one")
                .symbol()
                .shared_name_id()
                .map(|name| i64::from(name.get()))
        } else {
            None
        };
        result.paths.push(json!([
            codec::encode_path_id(*id),
            codec::encode_node(path.start().node()),
            codec::encode_node(path.end().node()),
            start.0,
            start.1,
            start.2,
            end.0,
            end.1,
            end.2,
            fixed,
            tail,
            terminal,
            codec::encode_path(path)
        ]));
    }
    for semantic in fragment.semantics() {
        if cancellation.is_cancelled() {
            return None;
        }
        let (key, shared) = semantic_cells(semantic.semantic());
        let metadata = semantic.site_metadata();
        let (owner_kind, owner_key, owner_shared) = match semantic.reference_owner() {
            None => (0, None, None),
            Some(None) => (1, None, None),
            Some(Some(owner)) => {
                let (key, shared) = semantic_cells(owner);
                (2, key, shared)
            }
        };
        result.semantics.push(json!([
            key,
            shared,
            codec::encode_node(semantic.node()),
            semantic.site().get(),
            resolution_rows::semantic_role_code(semantic.role()),
            resolution_rows::namespace_code(semantic.namespace()),
            metadata.map(|row| resolution_rows::site_kind_code(row.site_kind())),
            metadata.map(|row| row.start_byte()),
            metadata.map(|row| row.end_byte()),
            metadata.map(|row| row.unqualified()),
            owner_kind,
            owner_key,
            owner_shared,
            semantic
                .callable_receiver_origin()
                .map(resolution_rows::receiver_origin_code),
            metadata
                .and_then(|row| row.go_spelling_namespace())
                .map(resolution_rows::namespace_code),
            semantic.go_definition_namespaces().map(|set| set.bits()),
            metadata.is_some_and(|row| row.go_package_qualifier())
        ]));
    }
    for (ordinal, gap) in fragment.gaps().iter().enumerate() {
        if cancellation.is_cancelled() {
            return None;
        }
        let (covers, subject, endpoint, lookup) = match gap.frontier() {
            LoweringCoverageFrontier::Fragment => {
                (resolution_rows::COVERS_FRAGMENT, None, None, None)
            }
            LoweringCoverageFrontier::Enumeration => {
                (resolution_rows::COVERS_ENUMERATION, None, None, None)
            }
            LoweringCoverageFrontier::CandidateInventory { direction } => (
                resolution_rows::covers_candidate_inventory(direction),
                None,
                None,
                None,
            ),
            LoweringCoverageFrontier::Reference { semantic, node } => (
                resolution_rows::COVERS_REFERENCE,
                Some(semantic),
                Some(node),
                None,
            ),
            LoweringCoverageFrontier::Candidate {
                direction,
                endpoint,
                lookup,
            } => (
                resolution_rows::covers_candidate_endpoint(direction),
                None,
                Some(endpoint),
                lookup,
            ),
            LoweringCoverageFrontier::Type { frontier } => (
                resolution_rows::COVERS_TYPE_FRONTIER,
                Some(frontier),
                None,
                None,
            ),
        };
        // Reasons are fragment-local and never shared (#3737).
        let reason = codec::encode_semantic(gap.reason_semantic());
        assert!(reason >= 0, "a stage gap reason is never shared");
        let subject = subject.map_or((None, None), semantic_cells);
        let lookup = lookup.map_or((None, None), semantic_cells);
        // The gap's position in its fragment. `insert` adds the run of stage
        // gap keys it reserves, so the key is stage-owned and never a catalog
        // key (#3737).
        result.gaps.push(json!([
            covers,
            ordinal,
            reason,
            subject.0,
            subject.1,
            endpoint.map(codec::encode_node),
            lookup.0,
            lookup.1,
            gap.site().get(),
            resolution_rows::gap_origin_code(gap.origin())
        ]));
    }
    if cancellation.is_cancelled() {
        None
    } else {
        Some(result)
    }
}

impl PreparedStageLexical {
    pub(super) fn digest(&self) -> [u8; 32] {
        let mut digest = CanonicalHasher::new(b"bifrost-selected-stage-lexical:v1");
        digest.field("fragment", &self.fragment.as_bytes());
        digest.field("language", self.language.config_label().as_bytes());
        for (family, rows) in [
            ("nodes", &self.nodes),
            ("paths", &self.paths),
            ("semantics", &self.semantics),
            ("gaps", &self.gaps),
        ] {
            digest.field(
                family,
                serde_json::to_string(rows)
                    .expect("integer stage rows serialize")
                    .as_bytes(),
            );
        }
        digest.finish()
    }

    /// Candidate identity is exclusive across ordinary and stage sources, even
    /// when both bodies agree. Read scope does not narrow admission authority.
    pub(super) fn validate_ordinary_paths(
        &self,
        selection: &super::super::resolution_selection::SelectedResolutionMountInventory<'_>,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let host = self.fragment.ordinal();
        let requests = serde_json::to_string(
            &self
                .paths
                .iter()
                .map(|row| row[0].clone())
                .collect::<Vec<_>>(),
        )
        .expect("prepared path identity parameters");
        let mut query = selection.connection().prepare_cached(
            "SELECT request.key FROM json_each(?1) request CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=?2 CROSS JOIN main.resolution_paths path ON path.blob_id=mount.blob_id AND path.path=request.value-?3 WHERE request.value>=0 AND request.value<2305843009213693952 AND (request.value >> 32)=?2",
        )?;
        let mut rows = query.query(params![requests, host, i64::from(host) << 32])?;
        if let Some(row) = rows.next()? {
            let index: usize = row.get(0)?;
            return Err(StoreError::new(format!(
                "stage path duplicates ordinary candidate identity: host={host}, runtime={}",
                self.paths[index][0],
            )));
        }
        Ok(!cancellation.is_cancelled())
    }

    /// Compare overlapping defined ordinary nodes by complete structured payload.
    /// Catalog-only ordinary rows establish identity, not a node definition.
    pub(super) fn validate_ordinary_nodes(
        &self,
        selection: &super::super::resolution_selection::SelectedResolutionMountInventory<'_>,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        let mut requests = Vec::new();
        for (index, cells) in self.nodes.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            let node = codec::decode_node(cells[0].as_i64().expect("prepared node integer"));
            if let (Some(host), Some(key)) = (node.ordinal(), node.local_key()) {
                requests.push(json!([index, host, key]));
            }
        }
        let requests = serde_json::to_string(&requests).expect("ordinary node comparison requests");
        let connection = selection.connection();
        let names = selection.shared_name_table().interner(connection);
        let mut statement = connection.prepare_cached(
            "SELECT request.value->>0,request.value->>1,node.kind,node.semantic_local_key,node.semantic_shared_identity,node.target_local_key,node.target_boundary_key \
             FROM json_each(?1) request \
             JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=request.value->>1 \
             JOIN main.resolution_node_catalog node ON node.blob_id=mount.blob_id AND node.local_key=request.value->>2",
        )?;
        let mut rows = statement.query([requests])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            let Some(kind) = row.get::<_, Option<i64>>(2)? else {
                continue;
            };
            let index: usize = row.get(0)?;
            let host: u32 = row.get(1)?;
            let semantic_local: Option<u32> = row.get(3)?;
            let semantic_shared: Option<i64> = row.get(4)?;
            let target_local: Option<u32> = row.get(5)?;
            let target_boundary: Option<i64> = row.get(6)?;
            let expected_kind = decode_ordinary_node_kind(
                host,
                Some(kind),
                semantic_local,
                semantic_shared,
                target_local,
                target_boundary,
                &names,
            )
            .expect("defined ordinary node");
            let node = codec::decode_node(
                self.nodes[index][0]
                    .as_i64()
                    .expect("prepared node integer"),
            );
            let expected = node_cells(node, expected_kind);
            if self.nodes[index] != expected {
                return Err(StoreError::new(format!(
                    "stage node conflicts with ordinary structured payload: stage={:?}, ordinary={expected:?}",
                    self.nodes[index],
                )));
            }
        }
        Ok(!cancellation.is_cancelled())
    }

    pub(super) fn insert(
        self,
        connection: &Connection,
        producer: i64,
        host: SelectedResolutionMountOrdinal,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        assert_eq!(
            self.fragment.ordinal(),
            host.get(),
            "stage fragment belongs to its selected host"
        );
        assert_ne!(
            self.language,
            crate::analyzer::Language::None,
            "stage fragment has a semantic language"
        );
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let nodes = serde_json::to_string(&self.nodes).expect("stage node rows serialize");
        let conflict:bool=connection.prepare_cached("SELECT EXISTS(SELECT 1 FROM json_each(?1) input JOIN temp.selected_resolution_stage_nodes actual ON actual.node=input.value->>0 WHERE actual.kind IS NOT input.value->>1 OR actual.kind_semantic_key IS NOT input.value->>2 OR actual.kind_shared_id IS NOT input.value->>3 OR actual.kind_target_node IS NOT input.value->>4)")?.query_row([&nodes],|row|row.get(0))?;
        if conflict {
            return Err(StoreError::new(
                "selected stage graft has conflicting node kinds or payloads",
            ));
        }
        connection.prepare_cached("INSERT INTO temp.selected_resolution_stage_nodes(node,kind,kind_semantic_key,kind_shared_id,kind_target_node) SELECT value->>0,value->>1,value->>2,value->>3,value->>4 FROM json_each(?1) input WHERE NOT EXISTS(SELECT 1 FROM temp.selected_resolution_stage_nodes actual WHERE actual.node=input.value->>0)")?.execute([&nodes])?;
        connection.prepare_cached("INSERT INTO temp.selected_resolution_stage_node_owners(producer_id,node) SELECT ?1,value->>0 FROM json_each(?2)")?.execute(params![producer,nodes])?;
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        connection.prepare_cached("INSERT INTO temp.selected_resolution_stage_paths(host_ordinal,producer_id,path,start_node,end_node,start_lead_key,start_lead_shared,start_lead_scoped,end_lead_key,end_lead_shared,end_lead_scoped,end_fixed_key,end_open_tail,root_terminal_shared,body) SELECT ?1,?2,value->>0,value->>1,value->>2,value->>3,value->>4,value->>5,value->>6,value->>7,value->>8,value->>9,value->>10,value->>11,jsonb(value->>12) FROM json_each(?3)")?.execute(params![host.get(),producer,serde_json::to_string(&self.paths).expect("stage paths serialize")])?;
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        connection.prepare_cached("INSERT INTO temp.selected_resolution_stage_semantics(host_ordinal,producer_id,sequence,semantic_key,semantic_shared,node,source_site,role,namespace,site_kind,start_byte,end_byte,unqualified,owner_kind,owner_key,owner_shared,receiver_origin,go_spelling_namespace,go_definition_namespaces,go_package_qualifier) SELECT ?1,?2,key,value->>0,value->>1,value->>2,value->>3,value->>4,value->>5,value->>6,value->>7,value->>8,value->>9,value->>10,value->>11,value->>12,value->>13,value->>14,value->>15,value->>16 FROM json_each(?3)")?.execute(params![host.get(),producer,serde_json::to_string(&self.semantics).expect("stage semantics serialize")])?;
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        // Gap keys are a stage-owned run above the ordinary ordinals. Two
        // producers of one host that carry the same gap collapse on its content
        // tuple; the key only names the surviving row.
        if !self.gaps.is_empty() {
            let first = super::allocation::reserve_gap_keys(connection, host, self.gaps.len())?;
            let runtime_base = codec::encode_semantic(SemanticId::local(host.get(), 0)) + first;
            connection.prepare_cached("INSERT INTO temp.selected_resolution_stage_gaps(host_ordinal,producer_id,covers,gap_key,reason_key,subject_key,subject_shared,endpoint_node,lookup_key,lookup_shared,source_site,origin) SELECT ?1,?2,value->>0,?4+value->>1,value->>2,value->>3,value->>4,value->>5,value->>6,value->>7,value->>8,value->>9 FROM json_each(?3) input WHERE NOT EXISTS(SELECT 1 FROM temp.selected_resolution_stage_gaps actual INDEXED BY selected_resolution_stage_gap_tuple WHERE actual.host_ordinal=?1 AND actual.covers IS input.value->>0 AND actual.reason_key=input.value->>2 AND COALESCE(actual.subject_key,-1)=COALESCE(input.value->>3,-1) AND COALESCE(actual.subject_shared,-1)=COALESCE(input.value->>4,-1) AND COALESCE(actual.endpoint_node,-1)=COALESCE(input.value->>5,-1) AND COALESCE(actual.lookup_key,-1)=COALESCE(input.value->>6,-1) AND COALESCE(actual.lookup_shared,-1)=COALESCE(input.value->>7,-1) AND actual.source_site IS input.value->>8 AND actual.origin IS input.value->>9)")?.execute(params![host.get(),producer,serde_json::to_string(&self.gaps).expect("stage gaps serialize"),runtime_base])?;
        }
        Ok(!cancellation.is_cancelled())
    }
}

/// Project RP's committed source families directly through the assigned dense
/// coordinates. A missing correspondence fails the destination pair CHECK;
/// source rows are never dropped by an inner join or reconstructed from sites.
pub(super) fn insert_capsule_source(
    connection: &Connection,
    producer: i64,
    host: SelectedResolutionMountOrdinal,
    blob: i64,
    cancellation: &CancellationToken,
) -> Result<bool> {
    if cancellation.is_cancelled() {
        return Ok(false);
    }
    connection.prepare_cached(r#"
INSERT INTO temp.selected_resolution_stage_declarations(
 host_ordinal,producer_id,semantic_key,semantic_shared,identifier,kind,
 name_start_byte,name_end_byte,name_start_line,name_end_line,
 declaration_start_byte,declaration_end_byte,declaration_start_line,declaration_end_line)
SELECT ?1,?2,coordinate.runtime_key,coordinate.shared_id,source.identifier,source.kind,
 source.name_start_byte,source.name_end_byte,source.name_start_line,source.name_end_line,
 source.declaration_start_byte,source.declaration_end_byte,source.declaration_start_line,source.declaration_end_line
FROM main.resolution_capsule_declarations source
LEFT JOIN temp.selected_resolution_stage_semantic_coordinates coordinate
 ON coordinate.producer_id=?2 AND coordinate.dense_key=source.semantic_key
WHERE source.blob_id=?3
"#)?.execute(params![host.get(), producer, blob])?;
    if cancellation.is_cancelled() {
        return Ok(false);
    }
    let host_base = codec::encode_semantic(SemanticId::local(host.get(), 0));
    let cfg = crate::analyzer::store::resolution_prepare::rust_authority::encode_cfg(
        &brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition::Always,
    );
    connection
        .prepare_cached(
            r#"
INSERT INTO temp.selected_resolution_stage_reference_contexts(
 host_ordinal,producer_id,semantic_key,semantic_shared,source_site,host_occurrence,
 module_context,module_declaration,cfg,owner_kind,owner_key,owner_shared)
SELECT ?1,?2,coordinate.runtime_key,coordinate.shared_id,source.source_site,source.host_occurrence,
 source.module_context,source.module_declaration,jsonb(?5),source.reference_owner_kind,
 CASE WHEN source.reference_owner_kind=2 THEN ?4+source.host_owner_key END,NULL
FROM main.resolution_capsule_reference_contexts source
LEFT JOIN temp.selected_resolution_stage_semantic_coordinates coordinate
 ON coordinate.producer_id=?2 AND coordinate.dense_key=source.semantic_key
WHERE source.blob_id=?3
"#,
        )?
        .execute(params![host.get(), producer, blob, host_base, cfg])?;
    if cancellation.is_cancelled() {
        return Ok(false);
    }
    connection
        .prepare_cached(
            r#"
INSERT INTO temp.selected_resolution_stage_recipes(
 host_ordinal,producer_id,semantic_key,semantic_shared,semantic_language,namespace,spelling)
SELECT ?1,?2,coordinate.runtime_key,coordinate.shared_id,
 identity.semantic_language,identity.namespace,identity.spelling
FROM main.resolution_semantic_catalog catalog
JOIN main.resolution_identities identity
 ON identity.id=catalog.shared_identity AND identity.namespace IS NOT NULL
LEFT JOIN temp.selected_resolution_stage_semantic_coordinates coordinate
 ON coordinate.producer_id=?2 AND coordinate.dense_key=catalog.local_key
WHERE catalog.blob_id=?3
"#,
        )?
        .execute(params![host.get(), producer, blob])?;
    Ok(!cancellation.is_cancelled())
}

/// Resolve one query's reference semantics to their explicit stage nodes or
/// producer-proven ordinary site nodes. The result dies with the typed query.
pub(in crate::analyzer::store) fn reference_nodes(
    selection: &crate::analyzer::store::resolution_selection::SelectedResolutionMountInventory<'_>,
    requests: &[(SelectedResolutionMountOrdinal, SemanticId)],
    cancellation: &CancellationToken,
) -> Result<Option<Vec<Option<BindingNodeId>>>> {
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let requests = requests
        .iter()
        .map(|(host, semantic)| {
            let (runtime, shared) = semantic_cells(*semantic);
            json!([
                host.get(),
                runtime,
                shared,
                semantic.ordinal(),
                semantic.local_key()
            ])
        })
        .collect::<Vec<_>>();
    let mut result = vec![None; requests.len()];
    let requests =
        serde_json::to_string(&requests).expect("reference coordinate requests serialize");
    let read = crate::analyzer::store::resolution::with_resolution_read_progress_handler(
        selection.connection(),
        cancellation,
        |connection| {
            let mut statement = connection.prepare_cached(
                r#"
SELECT input.key,node.node
FROM json_each(?1) input
CROSS JOIN temp.selected_resolution_stage_nodes node
 ON node.kind=8 AND node.kind_semantic_key IS input.value->>1
 AND node.kind_shared_id IS input.value->>2
JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=input.value->>0
WHERE node.kind IN (8,9) AND EXISTS (
 SELECT 1 FROM temp.selected_resolution_stage_node_owners owner
 JOIN temp.selected_resolution_stage_producers producer ON producer.producer_id=owner.producer_id
 WHERE owner.node=node.node AND producer.host_ordinal=scope.mount_ordinal
)
UNION ALL
SELECT input.key,(mount.mount_ordinal << 32)+site.site
FROM json_each(?1) input
JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=input.value->>3
JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=scope.mount_ordinal
JOIN main.resolution_sites site ON site.blob_id=mount.blob_id AND site.site=input.value->>4
WHERE site.role=0
"#,
            )?;
            let mut rows = statement.query([requests])?;
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(false);
                }
                let position: usize = row.get(0)?;
                let node = codec::decode_node(row.get(1)?);
                if let Some(previous) = result[position] {
                    if previous != node {
                        return Err(StoreError::new(format!(
                            "selected reference has conflicting lexical nodes: {previous:?}, {node:?}"
                        )));
                    }
                } else {
                    result[position] = Some(node);
                }
            }
            Ok(!cancellation.is_cancelled())
        },
    );
    match read {
        Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => Ok(None),
        Err(error) => Err(error),
        Ok(false) => Ok(None),
        Ok(true) => Ok(Some(result)),
    }
}
