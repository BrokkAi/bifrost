//! Demand-local package metadata hydration. Language readers own membership.
use super::super::resolution_stage::codec;
use super::*;
use crate::analyzer::resolution::{
    LoweredPackageMember, LoweredPackageReference, SharedNameId, SharedNameInterner,
};
use brokk_bifrost_core::analyzer::resolution_facts::{ResolutionNamespace, ResolutionSiteId};

pub(crate) enum SelectedPackageRows<T> {
    Ready(Vec<T>),
    Cancelled,
}

pub(in crate::analyzer::store) const STAGED_PACKAGE_REFERENCES: &str = r#"
SELECT p.token_key,p.domain_shared,p.reference_key,p.source_site,p.root_scope_key,p.namespace,p.lookup_shared
FROM temp.selected_resolution_scope_mounts selected
JOIN temp.selected_resolution_stage_package_references p ON p.host_ordinal=selected.mount_ordinal
WHERE selected.mount_ordinal=?1
"#;

pub(in crate::analyzer::store) const ORDINARY_REFERENCES: &str = r#"
SELECT p.token_key,d.shared_identity,p.reference_key,p.source_site,p.root_scope_key,p.namespace,l.shared_identity
FROM temp.selected_resolution_scope_mounts selected
JOIN temp.selected_resolution_mounts mounted ON mounted.mount_ordinal=selected.mount_ordinal
JOIN main.resolution_package_references p ON p.blob_id=mounted.blob_id
JOIN main.resolution_semantic_catalog d ON d.blob_id=p.blob_id AND d.local_key=p.domain_key
JOIN main.resolution_semantic_catalog l ON l.blob_id=p.blob_id AND l.local_key=p.lookup_key
WHERE selected.mount_ordinal=?1
"#;

pub(in crate::analyzer::store) const STAGED_MEMBERS: &str = r#"
SELECT p.token_key,p.domain_shared,p.definition_key,p.source_site,p.root_scope_key,p.namespace,p.lookup_shared
FROM temp.selected_resolution_scope_mounts selected
JOIN temp.selected_resolution_stage_package_members candidate ON candidate.host_ordinal=selected.mount_ordinal AND candidate.lookup_shared=?2
JOIN temp.selected_resolution_stage_package_members p ON p.host_ordinal=candidate.host_ordinal
 AND p.definition_key=candidate.definition_key AND p.namespace=candidate.namespace
WHERE selected.mount_ordinal=?1
"#;

pub(in crate::analyzer::store) const ORDINARY_MEMBERS: &str = r#"
SELECT p.token_key,d.shared_identity,p.definition_key,p.source_site,p.root_scope_key,p.namespace,l.shared_identity
FROM temp.selected_resolution_scope_mounts selected
JOIN temp.selected_resolution_mounts mounted ON mounted.mount_ordinal=selected.mount_ordinal
JOIN main.resolution_semantic_catalog l ON l.blob_id=mounted.blob_id AND l.shared_identity=?2
JOIN main.resolution_package_members p ON p.blob_id=mounted.blob_id AND p.lookup_key=l.local_key
JOIN main.resolution_semantic_catalog d ON d.blob_id=p.blob_id AND d.local_key=p.domain_key
WHERE selected.mount_ordinal=?1
"#;

// A SQL row for this read only; both kinds use the same scalar column shape.
struct PackageCoordinates {
    token: SemanticId,
    domain: SemanticId,
    site_semantic: SemanticId,
    source_site: ResolutionSiteId,
    root_scope: BindingNodeId,
    namespace: ResolutionNamespace,
    lookup: SemanticId,
}

impl PackageCoordinates {
    fn staged(row: &rusqlite::Row<'_>) -> Result<Self> {
        Ok(Self {
            token: codec::decode_semantic(row.get(0)?),
            domain: codec::decode_semantic(-row.get::<_, i64>(1)?),
            site_semantic: codec::decode_semantic(row.get(2)?),
            source_site: ResolutionSiteId::new(row.get(3)?),
            root_scope: codec::decode_node(row.get(4)?),
            namespace: ResolutionNamespace::from_label(&row.get::<_, String>(5)?)
                .ok_or_else(|| StoreError::corrupt("invalid package namespace"))?,
            lookup: codec::decode_semantic(-row.get::<_, i64>(6)?),
        })
    }

    fn ordinary(
        row: &rusqlite::Row<'_>,
        ordinal: u32,
        names: &dyn SharedNameInterner,
    ) -> Result<Self> {
        Ok(Self {
            token: SemanticId::local(ordinal, row.get(0)?),
            domain: SemanticId::shared_name(
                names.from_persisted(SharedNameId::interned(row.get(1)?)),
            ),
            site_semantic: SemanticId::local(ordinal, row.get(2)?),
            source_site: ResolutionSiteId::new(row.get(3)?),
            root_scope: BindingNodeId::local(ordinal, row.get(4)?),
            namespace: ResolutionNamespace::from_label(&row.get::<_, String>(5)?)
                .ok_or_else(|| StoreError::corrupt("invalid package namespace"))?,
            lookup: SemanticId::shared_name(
                names.from_persisted(SharedNameId::interned(row.get(6)?)),
            ),
        })
    }

    fn reference(self) -> LoweredPackageReference {
        LoweredPackageReference {
            token: self.token,
            domain: self.domain,
            reference: self.site_semantic,
            source_site: self.source_site,
            root_scope: self.root_scope,
            namespace: self.namespace,
            lookup: self.lookup,
        }
    }
    fn member(self) -> LoweredPackageMember {
        LoweredPackageMember {
            token: self.token,
            domain: self.domain,
            definition: self.site_semantic,
            source_site: self.source_site,
            root_scope: self.root_scope,
            namespace: self.namespace,
            lookup: self.lookup,
        }
    }
}

impl SelectedResolutionOperation<'_, '_> {
    pub(crate) fn selected_package_references(
        &self,
        mount: SelectedResolutionMountOrdinal,
        cancellation: &CancellationToken,
    ) -> Result<SelectedPackageRows<LoweredPackageReference>> {
        let connection = self.ready.inventory.connection();
        let names = self.ready.shared_names();
        let mut result = BTreeMap::new();
        let mut statement = connection.prepare_cached(STAGED_PACKAGE_REFERENCES)?;
        let mut rows = statement.query([mount.get()])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(SelectedPackageRows::Cancelled);
            }
            let fact = PackageCoordinates::staged(row)?.reference();
            let key = (fact.reference, fact.namespace);
            if result
                .insert(key, fact)
                .is_some_and(|previous| previous != fact)
            {
                return Err(StoreError::corrupt(
                    "contradictory staged package references",
                ));
            }
        }
        let mut statement = connection.prepare_cached(ORDINARY_REFERENCES)?;
        let mut rows = statement.query([mount.get()])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(SelectedPackageRows::Cancelled);
            }
            let fact = PackageCoordinates::ordinary(row, mount.get(), &names)?.reference();
            result
                .entry((fact.reference, fact.namespace))
                .or_insert(fact);
        }
        if cancellation.is_cancelled() {
            return Ok(SelectedPackageRows::Cancelled);
        }
        Ok(SelectedPackageRows::Ready(result.into_values().collect()))
    }

    pub(crate) fn selected_package_members_for_lookup(
        &self,
        mount: SelectedResolutionMountOrdinal,
        lookup: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<SelectedPackageRows<LoweredPackageMember>> {
        let shared = lookup
            .shared_name_id()
            .expect("package lookup is a shared name");
        let connection = self.ready.inventory.connection();
        let names = self.ready.shared_names();
        let mut result = BTreeMap::new();
        let mut statement = connection.prepare_cached(STAGED_MEMBERS)?;
        let mut rows = statement.query(rusqlite::params![mount.get(), shared.get()])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(SelectedPackageRows::Cancelled);
            }
            let fact = PackageCoordinates::staged(row)?.member();
            let key = (fact.definition, fact.namespace);
            if result
                .insert(key, fact)
                .is_some_and(|previous| previous != fact)
            {
                return Err(StoreError::corrupt("contradictory staged package members"));
            }
        }
        if let Some(stored) = names.to_persisted(shared) {
            let mut statement = connection.prepare_cached(ORDINARY_MEMBERS)?;
            let mut rows = statement.query(rusqlite::params![mount.get(), stored.get()])?;
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(SelectedPackageRows::Cancelled);
                }
                let fact = PackageCoordinates::ordinary(row, mount.get(), &names)?.member();
                // A staged row for this identity wins even when it changed the
                // lookup name and therefore was absent from the lookup query.
                let mut stage = connection.prepare_cached(
                    "SELECT token_key,domain_shared,definition_key,source_site,root_scope_key,namespace,lookup_shared
                     FROM temp.selected_resolution_stage_package_members
                     WHERE host_ordinal=?1 AND definition_key=?2 AND namespace=?3",
                )?;
                let mut staged = stage.query(rusqlite::params![
                    mount.get(),
                    codec::encode_semantic(fact.definition),
                    fact.namespace.label()
                ])?;
                let mut authority = None;
                while let Some(row) = staged.next()? {
                    if cancellation.is_cancelled() {
                        return Ok(SelectedPackageRows::Cancelled);
                    }
                    let staged_fact = PackageCoordinates::staged(row)?.member();
                    if authority.is_some_and(|prior| prior != staged_fact) {
                        return Err(StoreError::corrupt("contradictory staged package members"));
                    }
                    authority = Some(staged_fact);
                }
                if let Some(staged_fact) = authority {
                    if staged_fact.lookup == lookup {
                        result.insert((staged_fact.definition, staged_fact.namespace), staged_fact);
                    }
                } else {
                    result
                        .entry((fact.definition, fact.namespace))
                        .or_insert(fact);
                }
            }
        }
        if cancellation.is_cancelled() {
            return Ok(SelectedPackageRows::Cancelled);
        }
        Ok(SelectedPackageRows::Ready(result.into_values().collect()))
    }
}
