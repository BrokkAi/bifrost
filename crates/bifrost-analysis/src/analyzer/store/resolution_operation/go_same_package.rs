//! Protected package peers selected by exact canonical Go package membership.

use super::go_context::GoDotImportContext;
use super::package_context::SelectedPackageRows;
use super::*;
use crate::analyzer::resolution::SelectedPackageBridgeDescriptor;

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

impl SelectedResolutionOperation<'_, '_> {
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
        let context =
            match self.go_dot_import_context(context_id, caller_path, source_role, cancellation)? {
                GoDotImportContext::Ready(context) => context,
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
        let mut statement = connection.prepare_cached(CALLER_PACKAGE)?;
        let mut rows = statement.query(rusqlite::params![context_id, version, source_role])?;
        let Some(row) = rows.next()? else {
            return Ok(GoDotImportContext::Unavailable);
        };
        let package: i64 = row.get(0)?;
        if rows.next()?.is_some() {
            // Multiple package placements do not authorize an arbitrary choice.
            return Ok(GoDotImportContext::Unavailable);
        }
        drop(rows);
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
        let SelectedPackageRows::Ready(references) =
            self.selected_package_references(source.ordinal(), cancellation)?
        else {
            return Ok(GoDotImportContext::Cancelled);
        };
        let completion = context.inventory_completion().clone();
        let mut bridges = Vec::new();
        for reference in references {
            for &peer in &peers {
                if cancellation.is_cancelled() {
                    return Ok(GoDotImportContext::Cancelled);
                }
                let SelectedPackageRows::Ready(members) =
                    self.selected_package_members_for_lookup(peer, reference.lookup, cancellation)?
                else {
                    return Ok(GoDotImportContext::Cancelled);
                };
                let target = self.ready.inventory.mount_record_by_ordinal(peer)?;
                for member in members {
                    bridges.push(SelectedPackageBridgeDescriptor::new(
                        source.fragment(),
                        target.fragment_id(),
                        Language::Go,
                        &reference,
                        &member,
                        completion.clone(),
                    ));
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
            Some(context) => GoDotImportContext::Ready(context),
            None => GoDotImportContext::Cancelled,
        })
    }
}
