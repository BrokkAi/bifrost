//! Dormant name-first namespace members. Nested types use member scope, not packages.
use super::csharp_units::{CSharpUnitPlacement, CSharpUnitReader};
use super::package_bridges::*;
use super::package_context::SelectedPackageRows;
use super::*;
use crate::analyzer::resolution::{
    LoweredPackageMember, LoweredPackageReference, SelectedPackageBridgeDescriptor,
    SharedNameInterner,
};
use crate::analyzer::store::WorkspaceSnapshotId;

pub const ORDINARY_CANDIDATES: &str = r#"
SELECT m.mount_ordinal,p.token_key,p.definition_key,p.domain_key,p.source_site,p.root_scope_key,p.namespace
FROM main.resolution_semantic_catalog l INDEXED BY resolution_semantic_catalog_shared_identity
CROSS JOIN main.resolution_package_members p INDEXED BY resolution_package_members_lookup
 ON p.blob_id=l.blob_id AND p.lookup_key=l.local_key
CROSS JOIN temp.selected_resolution_mounts m INDEXED BY selected_resolution_mounts_blob_ordinal ON m.blob_id=p.blob_id
CROSS JOIN temp.selected_resolution_scope_mounts a ON a.mount_ordinal=m.mount_ordinal
CROSS JOIN main.resolution_package_routes r ON r.blob_id=p.blob_id AND r.package_scope_node_key=p.root_scope_key
WHERE l.shared_identity=:lookup AND m.storage_language='csharp' AND p.namespace='type'
AND NOT EXISTS (SELECT 1 FROM json_each(:segments) w WHERE NOT EXISTS (
 SELECT 1 FROM main.resolution_package_route_segments s
 WHERE s.blob_id=r.blob_id AND s.package_scope_node_key=r.package_scope_node_key
 AND s.ordinal=CAST(w.key AS INTEGER) AND s.spelling=w.value))
AND NOT EXISTS (SELECT 1 FROM main.resolution_package_route_segments e
 WHERE e.blob_id=r.blob_id AND e.package_scope_node_key=r.package_scope_node_key
 AND e.ordinal>=json_array_length(:segments))
"#;
pub const STAGED_CANDIDATES: &str = r#"
SELECT m.mount_ordinal,m.blob_id,p.token_key,p.domain_shared,p.definition_key,p.source_site,p.root_scope_key,p.namespace,p.lookup_shared
FROM temp.selected_resolution_stage_package_members candidate
CROSS JOIN temp.selected_resolution_stage_package_members p ON p.host_ordinal=candidate.host_ordinal
 AND p.definition_key=candidate.definition_key AND p.namespace=candidate.namespace
CROSS JOIN temp.selected_resolution_mounts m ON m.mount_ordinal=p.host_ordinal
CROSS JOIN temp.selected_resolution_scope_mounts a ON a.mount_ordinal=m.mount_ordinal
WHERE candidate.lookup_shared=:runtime_lookup AND m.storage_language='csharp' AND p.namespace='type'
"#;
pub const VERIFY_NAMESPACE: &str = r#"
SELECT r.package_scope_node_key FROM main.resolution_package_routes r
WHERE r.blob_id=:blob AND r.package_scope_node_key=:scope
AND NOT EXISTS (SELECT 1 FROM json_each(:segments) w WHERE NOT EXISTS (
 SELECT 1 FROM main.resolution_package_route_segments s
 WHERE s.blob_id=r.blob_id AND s.package_scope_node_key=r.package_scope_node_key
 AND s.ordinal=CAST(w.key AS INTEGER) AND s.spelling=w.value))
AND NOT EXISTS (SELECT 1 FROM main.resolution_package_route_segments e
 WHERE e.blob_id=r.blob_id AND e.package_scope_node_key=r.package_scope_node_key
 AND e.ordinal>=json_array_length(:segments))
"#;

pub(super) struct CSharpNamespaceLevel {
    pub caller: CSharpUnitPlacement,
    pub path: Vec<String>,
}
pub(super) struct NamespaceMember {
    mount: SelectedResolutionMountOrdinal,
    fragment: BindingFragmentId,
    member: LoweredPackageMember,
}
pub(super) struct CSharpNamespaceRules<'a, 'unit, 'store, 'input> {
    ready: &'unit ReadySelectedResolution<'store, 'input>,
    units: &'a RefCell<CSharpUnitReader<'unit, 'store>>,
    source: BindingFragmentId,
}
impl PackagePlanRules for CSharpNamespaceRules<'_, '_, '_, '_> {
    type Source = CSharpNamespaceLevel;
    type Index = Vec<NamespaceMember>;
    fn read_index(
        &self,
        source: &Self::Source,
        references: &[LoweredPackageReference],
        cancellation: &CancellationToken,
    ) -> Result<SelectedPackageRows<Self::Index>> {
        let ready = self.ready;
        let conn = ready.inventory.connection();
        let names = ready.shared_names();
        let segments = serde_json::to_string(&source.path).expect("namespace segments serialize");
        let mut result = Vec::new();
        let mut seen = HashSet::default();
        for reference in references {
            if cancellation.is_cancelled() {
                return Ok(SelectedPackageRows::Cancelled);
            }
            let shared = reference
                .lookup
                .shared_name_id()
                .expect("package lookup is shared");
            let mut mounts = HashSet::default();
            if let Some(stored) = names.to_persisted(shared) {
                let mut statement = conn.prepare_cached(ORDINARY_CANDIDATES)?;
                let mut rows = statement.query(
                    rusqlite::named_params! {":lookup": stored.get(), ":segments": segments},
                )?;
                while let Some(row) = rows.next()? {
                    if cancellation.is_cancelled() {
                        return Ok(SelectedPackageRows::Cancelled);
                    }
                    mounts.insert(SelectedResolutionMountOrdinal::new(row.get(0)?));
                }
            }
            let mut statement = conn.prepare_cached(STAGED_CANDIDATES)?;
            let mut rows =
                statement.query(rusqlite::named_params! {":runtime_lookup": shared.get()})?;
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(SelectedPackageRows::Cancelled);
                }
                mounts.insert(SelectedResolutionMountOrdinal::new(row.get(0)?));
            }
            let mut mounts = mounts.into_iter().collect::<Vec<_>>();
            mounts.sort_unstable();
            for mount in mounts {
                if !seen.insert((mount, reference.lookup)) {
                    continue;
                }
                let SelectedPackageRows::Ready(members) = self
                    .ready
                    .selected_package_members_for_lookup(mount, reference.lookup, cancellation)?
                else {
                    return Ok(SelectedPackageRows::Cancelled);
                };
                let record = ready.inventory.mount_record_by_ordinal(mount)?;
                for member in members {
                    if cancellation.is_cancelled() {
                        return Ok(SelectedPackageRows::Cancelled);
                    }
                    let scope = member
                        .root_scope
                        .local_key()
                        .filter(|_| member.root_scope.ordinal() == Some(mount.get()))
                        .ok_or_else(|| {
                            StoreError::corrupt("C# namespace member has no mount-local root scope")
                        })?;
                    let matches = conn.prepare_cached(VERIFY_NAMESPACE)?.query_row(rusqlite::named_params! {":blob": record.blob_id(), ":scope": scope, ":segments": segments}, |_| Ok(())).optional()?.is_some();
                    if matches {
                        result.push(NamespaceMember {
                            mount,
                            fragment: record.fragment_id(),
                            member,
                        });
                    }
                }
            }
        }
        Ok(SelectedPackageRows::Ready(result))
    }
}
impl PackagePairingRules for CSharpNamespaceRules<'_, '_, '_, '_> {
    type Bridges = Self;
    fn matching_members<'a>(
        &'a self,
        source: &'a Self::Source,
        index: &'a Self::Index,
        reference: &'a LoweredPackageReference,
    ) -> impl Iterator<Item = PackageBridgeTarget<'a, CSharpUnitPlacement>> {
        index
            .iter()
            .filter(move |entry| {
                entry.member.lookup == reference.lookup
                    && entry.member.namespace == reference.namespace
            })
            .map(move |entry| PackageBridgeTarget {
                member: &entry.member,
                target_fragment: entry.fragment,
                target_mount: entry.mount,
                extra: source.caller.clone(),
            })
    }
}
impl PackageBridgeRules for CSharpNamespaceRules<'_, '_, '_, '_> {
    type Extra = CSharpUnitPlacement;
    type Admission = PackageBridgeAdmission<BindingFragmentId>;
    fn admit(
        &self,
        ready: &ReadySelectedResolution<'_, '_>,
        pair: &PackageBridgePair<'_, Self::Extra>,
        _cancellation: &CancellationToken,
    ) -> Result<Option<Self::Admission>> {
        let mount = ready.inventory.mount_record_by_ordinal(pair.target_mount)?;
        let mut units = self.units.borrow_mut();
        let targets = units.placements(mount.persisted_relative_path())?;
        let access =
            units.read_access(Some(std::slice::from_ref(&pair.extra)), targets.as_deref())?;
        Ok(access
            .completion(&ResolutionCompletion::Complete)
            .map(|completion| PackageBridgeAdmission {
                evidence: pair.target_fragment,
                completion,
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
            Language::CSharp,
            pair.reference,
            pair.member,
            admission.completion,
        )
    }
}

pub(super) struct AdmittedNamespaceMember {
    pub mount: SelectedResolutionMountOrdinal,
    pub member: LoweredPackageMember,
    pub completion: ResolutionCompletion,
}

/// C# has no set admission: retain targets from the shared ordered pair join.
pub(super) fn namespace_members<'unit, 'store, 'input>(
    ready: &'unit ReadySelectedResolution<'store, 'input>,
    units: &RefCell<CSharpUnitReader<'unit, 'store>>,
    source: BindingFragmentId,
    sources: &[CSharpNamespaceLevel],
    references: &[LoweredPackageReference],
    cancellation: &CancellationToken,
) -> Result<SelectedPackageRows<Vec<AdmittedNamespaceMember>>> {
    let rules = CSharpNamespaceRules {
        ready,
        units,
        source,
    };
    let SelectedPackageRows::Ready(plan) =
        build_package_plan(sources, references, &rules, cancellation)?
    else {
        return Ok(SelectedPackageRows::Cancelled);
    };
    let mut targets = Vec::new();
    for pair in package_bridge_pairs(&plan, references, &rules, cancellation) {
        if cancellation.is_cancelled() {
            return Ok(SelectedPackageRows::Cancelled);
        }
        if let Some(admission) = rules.admit(ready, &pair, cancellation)? {
            targets.push(AdmittedNamespaceMember {
                mount: pair.target_mount,
                member: *pair.member,
                completion: admission.completion,
            });
        }
    }
    Ok(if cancellation.is_cancelled() {
        SelectedPackageRows::Cancelled
    } else {
        SelectedPackageRows::Ready(targets)
    })
}

/// Exercise the dormant A5 adapter on selected source references, returning exact
/// admitted declaration coordinates. Namespace paths are supplied structurally.
#[doc(hidden)]
pub fn probe_namespace_members(
    operation: &SelectedResolutionOperation<'_, '_>,
    snapshot: &WorkspaceSnapshotId,
    caller: &str,
    namespace: &[String],
    cancellation: &CancellationToken,
) -> Result<Option<Vec<(String, String)>>> {
    let Some(mount) = operation.mount_table().mount_for_path("csharp", caller)? else {
        return Ok(None);
    };
    let mut units = CSharpUnitReader::new(
        &operation.ready.inventory,
        snapshot,
        &operation.ready.context_identities,
    )?;
    let Some(callers) = units.placements(caller)? else {
        return Ok(None);
    };
    let SelectedPackageRows::Ready(references) = operation
        .ready
        .selected_package_references(mount.ordinal(), cancellation)?
    else {
        return Ok(None);
    };
    let references = super::package_context::unique_package_references_by_token(&references)?;
    let sources = callers
        .into_iter()
        .map(|caller| CSharpNamespaceLevel {
            caller,
            path: namespace.to_vec(),
        })
        .collect::<Vec<_>>();
    let units = RefCell::new(units);
    let SelectedPackageRows::Ready(admitted) = namespace_members(
        &operation.ready,
        &units,
        mount.fragment(),
        &sources,
        &references,
        cancellation,
    )?
    else {
        return Ok(None);
    };
    let definitions = admitted
        .iter()
        .map(|target| target.member.definition)
        .collect::<Vec<_>>();
    let SelectedNativeDefinitions::Ready(projected) =
        native_units::project_native_definition_units(
            &operation.ready,
            &definitions,
            cancellation,
            &ResolutionSession::unbounded(),
        )?
    else {
        return Ok(None);
    };
    assert_eq!(admitted.len(), projected.len());
    let mut result = Vec::new();
    for (target, (_, definition)) in admitted.into_iter().zip(projected) {
        let SelectedNativeDefinition::Unit(unit) = definition else {
            return Err(StoreError::corrupt(
                "C# namespace member is not a source declaration",
            ));
        };
        let record = operation
            .ready
            .inventory
            .mount_record_by_ordinal(target.mount)?;
        result.push((
            record.persisted_relative_path().to_owned(),
            unit.fq_name_str().to_owned(),
        ));
    }
    result.sort_unstable();
    result.dedup();
    Ok(Some(result))
}
