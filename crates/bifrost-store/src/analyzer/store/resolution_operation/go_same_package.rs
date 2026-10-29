//! Protected package peers selected by exact canonical Go package membership.

use super::file_context::{PackagePeerRelation, PeerSelection};
use super::go_context::{GoContextSelection, GoDotImportContext};
use super::package_bridges::{
    PackageBridgeAdmission, PackageBridgePair, PackageBridgeRules, PackageBridgeTarget,
    PackagePairingRules, PackagePlanRules, drive_package_bridges,
};
use super::package_context::{SelectedPackageRows, unique_package_references_by_token};
use super::placement_access::read_placement_rows;
use super::*;
use crate::analyzer::resolution::{
    LoweredPackageMember, LoweredPackageReference, SelectedPackageBridgeDescriptor,
};

impl PackagePeerRelation for PeerSelection {
    const RELATION: &'static str = PACKAGE_PEER_MOUNTS;

    fn params(&self) -> impl rusqlite::Params {
        (self.context_id, self.package, self.source_role.as_str())
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub const PACKAGE_MEMBER_READ_STATEMENTS_FOR_TEST: [&str; 2] = [
    super::package_context::ORDINARY_MEMBERS_BY_MOUNT,
    super::package_context::STAGED_MEMBERS_BY_MOUNT,
];

struct GoPackagePlanRules<'a, 'store, 'operation> {
    operation: &'a SelectedResolutionOperation<'store, 'operation>,
    request: &'a super::file_context::PeerSelection,
}

struct GoPackageIndex {
    target_fragment: BindingFragmentId,
    members: Arc<HashMap<SemanticId, Vec<LoweredPackageMember>>>,
}

impl PackagePlanRules for GoPackagePlanRules<'_, '_, '_> {
    type Source = SelectedResolutionMountOrdinal;
    type Index = GoPackageIndex;

    fn read_index(
        &self,
        peer: &Self::Source,
        _references: &[LoweredPackageReference],
        cancellation: &CancellationToken,
    ) -> Result<SelectedPackageRows<Self::Index>> {
        let Some(members) =
            self.operation
                .read_package_peer_members(self.request, *peer, cancellation)?
        else {
            return Ok(SelectedPackageRows::Cancelled);
        };
        let target = self
            .operation
            .ready
            .inventory
            .mount_record_by_ordinal(*peer)?;
        Ok(SelectedPackageRows::Ready(GoPackageIndex {
            target_fragment: target.fragment_id(),
            members,
        }))
    }
}

impl PackagePairingRules for GoPackagePlanRules<'_, '_, '_> {
    type Bridges = GoPackageBridgeRules;

    fn matching_members<'a>(
        &'a self,
        peer: &'a Self::Source,
        index: &'a Self::Index,
        reference: &'a LoweredPackageReference,
    ) -> impl Iterator<Item = PackageBridgeTarget<'a, ()>> {
        index
            .members
            .get(&reference.lookup)
            .into_iter()
            .flatten()
            .map(move |member| PackageBridgeTarget {
                member,
                target_fragment: index.target_fragment,
                target_mount: *peer,
                extra: (),
            })
    }
}

struct GoPackageBridgeRules {
    source: BindingFragmentId,
    completion: ResolutionCompletion,
}

impl PackageBridgeRules for GoPackageBridgeRules {
    type Extra = ();
    type Admission = PackageBridgeAdmission<BindingFragmentId>;

    fn admit(
        &self,
        _operation: &ReadySelectedResolution<'_, '_>,
        pair: &PackageBridgePair<'_, Self::Extra>,
        _cancellation: &CancellationToken,
    ) -> Result<Option<Self::Admission>> {
        Ok(Some(PackageBridgeAdmission {
            evidence: pair.target_fragment,
            completion: self.completion.clone(),
        }))
    }

    fn descriptor(
        &self,
        pair: &PackageBridgePair<'_, Self::Extra>,
        admission: Self::Admission,
    ) -> SelectedPackageBridgeDescriptor {
        SelectedPackageBridgeDescriptor::new(
            self.source,
            admission.evidence,
            Language::Go,
            pair.reference,
            pair.member,
            admission.completion,
        )
    }
}

#[doc(hidden)]
pub static CALLER_PACKAGE: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!(
        r#"
SELECT package.package_id
FROM ({}) caller
JOIN main.go_package_instances package
  ON package.context_id=caller.context_id AND package.package_id=caller.package_id
WHERE caller.context_id=?1 AND caller.file_version_id=?2 AND caller.source_role=?3
 AND ((?3 IN ('go','ignored') AND package.for_test='')
   OR (?3 IN ('test','xtest') AND package.for_test<>'')
   OR (?3='test' AND package.for_test='' AND package.complete=0
       AND NOT EXISTS(
         SELECT 1
         FROM ({}) selected_test
         JOIN main.go_package_instances selected_package
           ON selected_package.context_id=selected_test.context_id
          AND selected_package.package_id=selected_test.package_id
         WHERE selected_test.context_id=caller.context_id
           AND selected_test.file_version_id=caller.file_version_id
           AND selected_test.source_role='test'
           AND selected_package.for_test<>''
       ))
   OR (?3 IN ('test','xtest') AND package.provider_provenance='source_inventory'))
"#,
        super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str(),
        super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str()
    )
});

#[doc(hidden)]
pub const PACKAGE_PEER_MOUNTS: &str = r#"
SELECT mounted.mount_ordinal
FROM temp.selected_go_context_source_files provider
JOIN temp.selected_resolution_mounts mounted ON mounted.file_version_id=provider.file_version_id
JOIN temp.selected_resolution_scope_mounts selected ON selected.mount_ordinal=mounted.mount_ordinal
WHERE provider.context_id=?1 AND provider.package_id=?2
 AND provider.source_role IN ('go',?3) AND mounted.storage_language='go'
UNION ALL
SELECT placed.mount_ordinal
FROM temp.selected_go_context_source_files provider
JOIN temp.selected_go_transient_placements placed ON placed.file_version_id=provider.file_version_id
JOIN temp.selected_resolution_scope_mounts selected ON selected.mount_ordinal=placed.mount_ordinal
WHERE provider.context_id=?1 AND provider.package_id=?2
 AND provider.source_role IN ('go',?3)
"#;

// Inventory membership is diagnostic evidence, not selected candidate authority.
// Bind the inventory publication to the selected context's exact source revision.
// A member that source admission refused is an unselected source input too: its
// declarations are unknown, so it can add or shadow a same-package name.
pub(crate) static POINT_PACKAGE_WITH_UNSELECTED_SOURCE: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            r#"
SELECT DISTINCT package.tool_import_path
FROM temp.selected_go_context_source_files AS caller
JOIN main.go_package_instances AS package
  ON package.package_id=caller.package_id
JOIN main.go_context_publications AS publication
  ON publication.context_id=caller.context_id
JOIN main.go_context_selections AS selection
  ON selection.selection_id=publication.selection_id
WHERE caller.context_id=?1 AND caller.file_version_id=?2
 AND caller.package_id=?4
 AND (
  EXISTS(
    SELECT 1 FROM json_each(package.gaps) AS gap
    WHERE json_extract(gap.value,'$.code') IN ('unselected_source_input','source_admission_refused')
  )
  OR EXISTS(
    SELECT 1
    FROM main.go_context_selections AS inventory_selection
    JOIN main.go_context_publications AS inventory_head
      ON inventory_head.selection_id=inventory_selection.selection_id
    JOIN ({}) AS inventory_caller
      ON inventory_caller.context_id=inventory_head.context_id
     AND inventory_caller.file_version_id=caller.file_version_id
     AND inventory_caller.source_role=caller.source_role
    JOIN temp.selected_go_context_source_files AS sibling
      ON sibling.context_id=inventory_caller.context_id
     AND sibling.package_id=inventory_caller.package_id
    JOIN main.workspace_file_versions AS version
      ON version.file_version_id=sibling.file_version_id
    JOIN main.blobs AS blob
      ON blob.blob_oid=version.blob_oid
     AND blob.lang=version.lang
     AND blob.generation=version.generation
    JOIN main.source_go_manifests AS facts ON facts.blob_id=blob.id
    WHERE inventory_selection.workspace_id=selection.workspace_id
      AND inventory_selection.lang=selection.lang
      AND inventory_selection.generation=selection.generation
      AND inventory_selection.derivation_version=selection.derivation_version
      AND inventory_selection.profile_digest=?3
      AND sibling.source_role IN ('go',caller.source_role)
      AND sibling.file_version_id<>caller.file_version_id
      AND facts.has_build_constraints=1
  )
 )
"#,
            super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str()
        )
    });

impl SelectedResolutionOperation<'_, '_> {
    /// Exercise the private production peer reader from real-language tests.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn go_package_peers_for_test(
        &self,
        context_id: i64,
        package: i64,
        source_role: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<SelectedResolutionMountOrdinal>>> {
        self.read_package_peers(
            &PeerSelection {
                context_id,
                package,
                source_role: source_role.to_owned(),
            },
            cancellation,
        )
    }

    pub(super) fn go_selected_package_id(
        &self,
        context_id: i64,
        file_version_id: i64,
        source_role: &str,
    ) -> Result<Option<i64>> {
        let rows = read_placement_rows(
            &self.ready.inventory,
            CALLER_PACKAGE.as_str(),
            rusqlite::params![context_id, file_version_id, source_role],
            |row: &rusqlite::Row<'_>| Ok(row.get(0)?),
        )?;
        let [package_id] = rows.as_slice() else {
            return Ok(None);
        };
        Ok(Some(*package_id))
    }

    /// Name the package whose own unselected-source gap or constrained source
    /// inventory can add or shadow a same-package member. Point lookup consults
    /// this only after the native member answer is already incomplete; reverse
    /// inventory has its own build-selection contract and must not use this read.
    #[doc(hidden)]
    pub fn go_point_package_with_unselected_source(
        &self,
        context_id: i64,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<String>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(caller) = self.mount_table().mount_for_path("go", caller_path)? else {
            return Ok(None);
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
            return Ok(None);
        };
        let Some(unit) =
            self.go_package_stage_unit_for_path(context_id, caller_path, cancellation)?
        else {
            return Ok(None);
        };
        let package = self
            .ready
            .inventory
            .connection()
            .query_row(
                POINT_PACKAGE_WITH_UNSELECTED_SOURCE.as_str(),
                rusqlite::params![
                    context_id,
                    version,
                    super::super::go_package_context::source_inventory_profile(),
                    unit.package_id
                ],
                |row| row.get(0),
            )
            .optional()?;
        Ok(if cancellation.is_cancelled() {
            None
        } else {
            package
        })
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
        let outcome = self.go_package_context_for_selection(
            context_id,
            caller_path,
            source_role,
            &selection,
            cancellation,
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
        let peer_request = super::file_context::PeerSelection {
            context_id,
            package,
            source_role: source_role.to_owned(),
        };
        let Some(peers) = self.read_package_peers(&peer_request, cancellation)? else {
            return Ok(GoDotImportContext::Cancelled);
        };
        let SelectedPackageRows::Ready(references) =
            self.selected_package_references(source.ordinal(), cancellation)?
        else {
            return Ok(GoDotImportContext::Cancelled);
        };
        let references = unique_package_references_by_token(&references)?;
        let assembly = drive_package_bridges(
            &self.ready,
            &peers,
            &references,
            &GoPackagePlanRules {
                operation: self,
                request: &peer_request,
            },
            &GoPackageBridgeRules {
                source: source.fragment(),
                completion: context.inventory_completion().clone(),
            },
            cancellation,
        )?;
        if assembly
            .completion
            .contains_reason(ResolutionIncompleteReason::Cancelled)
        {
            return Ok(GoDotImportContext::Cancelled);
        }
        let result = context.extend_package_bridges(
            assembly.descriptors,
            cancellation,
            &selected_mount_lookup(self.mount_table()),
        )?;
        Ok(match result {
            Some(context) => GoDotImportContext::Ready { context, inventory },
            None => GoDotImportContext::Cancelled,
        })
    }
}
