//! Protected package peers selected by exact canonical Go package membership.

use super::go_context::{GoContextSelection, GoDotImportContext};
use super::package_context::{SelectedPackageRows, unique_package_references_by_token};
use super::*;
use crate::analyzer::resolution::{LoweredPackageMember, SelectedPackageBridgeDescriptor};

#[derive(Default)]
pub(super) struct GoPackageMemberIndexCache {
    packages: HashMap<(i64, i64, String), GoPackageMemberIndexes>,
    memo_hits: u64,
}

impl GoPackageMemberIndexCache {
    fn peers(&mut self, key: &(i64, i64, String)) -> Option<Vec<SelectedResolutionMountOrdinal>> {
        let peers = self.packages.get(key).map(|indexes| indexes.peers.clone());
        if peers.is_some() {
            self.memo_hits += 1;
        }
        peers
    }

    fn insert_peers(
        &mut self,
        key: (i64, i64, String),
        peers: Vec<SelectedResolutionMountOrdinal>,
    ) {
        self.packages.insert(
            key,
            GoPackageMemberIndexes {
                peers,
                members_by_peer: HashMap::default(),
            },
        );
    }

    fn has_members(
        &mut self,
        key: &(i64, i64, String),
        peer: SelectedResolutionMountOrdinal,
    ) -> bool {
        let has_members = self
            .packages
            .get(key)
            .expect("Go package peer list was cached")
            .members_by_peer
            .contains_key(&peer);
        if has_members {
            self.memo_hits += 1;
        }
        has_members
    }

    fn insert_members(
        &mut self,
        key: &(i64, i64, String),
        peer: SelectedResolutionMountOrdinal,
        members: HashMap<SemanticId, Vec<LoweredPackageMember>>,
    ) {
        self.packages
            .get_mut(key)
            .expect("Go package peer list was cached")
            .members_by_peer
            .insert(peer, members);
    }

    fn members(
        &self,
        key: &(i64, i64, String),
        peer: SelectedResolutionMountOrdinal,
    ) -> &HashMap<SemanticId, Vec<LoweredPackageMember>> {
        self.packages
            .get(key)
            .expect("Go package peer list was cached")
            .members_by_peer
            .get(&peer)
            .expect("Go package member index was loaded")
    }
}

impl super::graph_stage::GraphStageHelperTables for GoPackageMemberIndexCache {
    fn memo_stats(&self) -> super::graph_stage::GraphStageMemoStats {
        super::graph_stage::GraphStageMemoStats {
            hits: self.memo_hits,
            distinct_keys: self.packages.len()
                + self
                    .packages
                    .values()
                    .map(|indexes| indexes.members_by_peer.len())
                    .sum::<usize>(),
        }
    }
}

#[derive(Default)]
struct GoPackageMemberIndexes {
    peers: Vec<SelectedResolutionMountOrdinal>,
    members_by_peer:
        HashMap<SelectedResolutionMountOrdinal, HashMap<SemanticId, Vec<LoweredPackageMember>>>,
}

pub(in crate::analyzer::store) const CALLER_PACKAGE: &str = r#"
SELECT package.package_id
FROM main.go_context_source_files caller
JOIN main.go_package_instances package
  ON package.context_id=caller.context_id AND package.package_id=caller.package_id
WHERE caller.context_id=?1 AND caller.file_version_id=?2 AND caller.source_role=?3
 AND ((?3='go' AND package.for_test='')
   OR (?3 IN ('test','xtest') AND package.for_test<>'')
   OR (?3='test' AND package.for_test='' AND package.complete=0
       AND NOT EXISTS(
         SELECT 1
         FROM main.go_context_source_files selected_test
         JOIN main.go_package_instances selected_package
           ON selected_package.context_id=selected_test.context_id
          AND selected_package.package_id=selected_test.package_id
         WHERE selected_test.context_id=caller.context_id
           AND selected_test.file_version_id=caller.file_version_id
           AND selected_test.source_role='test'
           AND selected_package.for_test<>''
       ))
   OR (?3 IN ('test','xtest') AND package.provider_provenance='source_inventory'))
"#;

pub(in crate::analyzer::store) const PACKAGE_PEER_MOUNTS: &str = r#"
SELECT mounted.mount_ordinal
FROM main.go_context_source_files provider
JOIN temp.selected_resolution_mounts mounted ON mounted.file_version_id=provider.file_version_id
JOIN temp.selected_resolution_scope_mounts selected ON selected.mount_ordinal=mounted.mount_ordinal
WHERE provider.context_id=?1 AND provider.package_id=?2
 AND provider.source_role IN ('go',?3) AND mounted.storage_language='go'
UNION ALL
SELECT placed.mount_ordinal
FROM main.go_context_source_files provider
JOIN temp.selected_go_transient_placements placed ON placed.file_version_id=provider.file_version_id
JOIN temp.selected_resolution_scope_mounts selected ON selected.mount_ordinal=placed.mount_ordinal
WHERE provider.context_id=?1 AND provider.package_id=?2
 AND provider.source_role IN ('go',?3)
"#;

const PACKAGE_HAS_BUILD_CONSTRAINED_SIBLING: &str = r#"
SELECT EXISTS(
  SELECT 1
  FROM main.go_context_source_files AS caller
  JOIN main.go_package_files AS sibling
    ON sibling.package_id=caller.package_id
  JOIN main.workspace_file_versions AS version
    ON version.file_version_id=sibling.file_version_id
  JOIN main.blobs AS blob
    ON blob.blob_oid=version.blob_oid
   AND blob.lang=version.lang
   AND blob.generation=version.generation
  JOIN main.source_go_manifests AS facts ON facts.blob_id=blob.id
  WHERE caller.context_id=?1
    AND caller.file_version_id=?2
    AND sibling.source_role IN ('go',caller.source_role)
    AND sibling.file_version_id<>caller.file_version_id
    AND facts.has_build_constraints=1
)
"#;

impl SelectedResolutionOperation<'_, '_> {
    pub(super) fn go_selected_package_id(
        &self,
        context_id: i64,
        file_version_id: i64,
        source_role: &str,
    ) -> Result<Option<i64>> {
        let mut statement = self
            .ready
            .inventory
            .connection()
            .prepare_cached(CALLER_PACKAGE)?;
        let mut rows =
            statement.query(rusqlite::params![context_id, file_version_id, source_role])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let package_id = row.get(0)?;
        if rows.next()?.is_some() {
            return Ok(None);
        }
        Ok(Some(package_id))
    }

    /// Whether a saved peer omitted from the selected build can add or shadow
    /// a same-package member. Point lookup consults this only after the native
    /// member answer is already incomplete; reverse inventory has its own
    /// build-selection contract and must not use this predicate.
    pub(crate) fn go_point_has_build_constrained_sibling(
        &self,
        context_id: i64,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let Some(caller) = self.mount_table().mount_for_path("go", caller_path)? else {
            return Ok(false);
        };
        let record = self
            .ready
            .inventory
            .mount_record_by_ordinal(caller.ordinal())?;
        let Some(version) = super::go_context::go_placement_file_version(
            self.ready.inventory.connection(),
            &record,
        )?
        else {
            return Ok(false);
        };
        let constrained: bool = self.ready.inventory.connection().query_row(
            PACKAGE_HAS_BUILD_CONSTRAINED_SIBLING,
            rusqlite::params![context_id, version],
            |row| row.get(0),
        )?;
        Ok(constrained && !cancellation.is_cancelled())
    }

    /// Compose dot imports and protected same-package peers. Test files prefer
    /// a selected ForTest instance; an incomplete source-inventory fallback
    /// may use the same-package source row but keeps the result incomplete.
    /// The dot phase binds publication freshness.
    pub(crate) fn go_package_context(
        &self,
        context_id: i64,
        caller_path: &str,
        source_role: &str,
        cancellation: &CancellationToken,
    ) -> Result<GoDotImportContext> {
        if cancellation.is_cancelled() {
            return Ok(GoDotImportContext::Cancelled);
        }
        let Some(selection) = self.go_context_selection(context_id, source_role)? else {
            return Ok(GoDotImportContext::Unavailable);
        };
        let mut member_cache = self.go_package_member_indexes.borrow_mut();
        let outcome = self.go_package_context_for_selection(
            context_id,
            caller_path,
            source_role,
            &selection,
            cancellation,
            &mut member_cache,
        )?;
        if let GoDotImportContext::Ready { inventory, .. } = &outcome {
            self.record_go_package_inventory_state(inventory);
        }
        Ok(outcome)
    }

    pub(super) fn go_package_context_for_selection(
        &self,
        context_id: i64,
        caller_path: &str,
        source_role: &str,
        selection: &GoContextSelection,
        cancellation: &CancellationToken,
        member_cache: &mut GoPackageMemberIndexCache,
    ) -> Result<GoDotImportContext> {
        let (context, inventory) = match self.go_dot_import_context_for_selection(
            context_id,
            caller_path,
            source_role,
            selection,
            cancellation,
        )? {
            GoDotImportContext::Ready { context, inventory } => (context, inventory),
            other => return Ok(other),
        };
        let Some(source) = self.mount_table().mount_for_path("go", caller_path)? else {
            return Ok(GoDotImportContext::Unavailable);
        };
        let source_record = self
            .ready
            .inventory
            .mount_record_by_ordinal(source.ordinal())?;
        let connection = self.ready.inventory.connection();
        let Some(version) =
            super::go_context::go_placement_file_version(connection, &source_record)?
        else {
            return Ok(GoDotImportContext::Unavailable);
        };
        let Some(package) = self.go_selected_package_id(context_id, version, source_role)? else {
            // Multiple package placements do not authorize an arbitrary choice.
            return Ok(GoDotImportContext::Unavailable);
        };
        let cache_key = (context_id, package, source_role.to_owned());
        let peers = if let Some(peers) = member_cache.peers(&cache_key) {
            peers
        } else {
            let mut statement = connection.prepare_cached(PACKAGE_PEER_MOUNTS)?;
            let mut rows = statement.query(rusqlite::params![context_id, package, source_role])?;
            let mut peers = Vec::new();
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(GoDotImportContext::Cancelled);
                }
                peers.push(SelectedResolutionMountOrdinal::new(row.get(0)?));
            }
            drop(rows);
            member_cache.insert_peers(cache_key.clone(), peers.clone());
            peers
        };
        let SelectedPackageRows::Ready(references) =
            self.selected_package_references(source.ordinal(), cancellation)?
        else {
            return Ok(GoDotImportContext::Cancelled);
        };
        let references = unique_package_references_by_token(&references)?;
        let completion = context.inventory_completion().clone();
        let mut bridges = Vec::new();
        if !references.is_empty() {
            for &peer in &peers {
                if !member_cache.has_members(&cache_key, peer) {
                    let SelectedPackageRows::Ready(members_by_lookup) =
                        self.selected_package_members_by_lookup(peer, cancellation)?
                    else {
                        return Ok(GoDotImportContext::Cancelled);
                    };
                    member_cache.insert_members(&cache_key, peer, members_by_lookup);
                }
                let members_by_lookup = member_cache.members(&cache_key, peer);
                let target = self.ready.inventory.mount_record_by_ordinal(peer)?;
                for reference in &references {
                    if cancellation.is_cancelled() {
                        return Ok(GoDotImportContext::Cancelled);
                    }
                    if let Some(members) = members_by_lookup.get(&reference.lookup) {
                        for member in members {
                            bridges.push(SelectedPackageBridgeDescriptor::new(
                                source.fragment(),
                                target.fragment_id(),
                                Language::Go,
                                reference,
                                member,
                                completion.clone(),
                            ));
                        }
                    }
                }
            }
        }
        let mounts = self.mount_table();
        let result = context.extend_package_bridges(bridges, cancellation, &|fragment| {
            Ok(mounts
                .mount_for_fragment(fragment)?
                .map(|mount| (mount.ordinal(), mount.semantic_language())))
        })?;
        Ok(match result {
            Some(context) => GoDotImportContext::Ready { context, inventory },
            None => GoDotImportContext::Cancelled,
        })
    }
}
