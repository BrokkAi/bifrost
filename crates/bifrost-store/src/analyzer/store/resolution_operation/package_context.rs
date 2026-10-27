//! Demand-local package metadata hydration. Language readers own membership.
use super::super::resolution_stage::{StageFamily, codec};
use super::*;
use crate::analyzer::resolution::{
    LoweredPackageMember, LoweredPackageReference, SharedNameId, SharedNameInterner,
};
use brokk_bifrost_core::analyzer::resolution_facts::{ResolutionNamespace, ResolutionSiteId};

#[doc(hidden)]
pub enum SelectedPackageRows<T> {
    Ready(T),
    Cancelled,
}

// Unlike ordinary candidate reads, this query reads stage rows and their
// shadowing of ordinary references. Both committed content and direct TEMP
// writes must invalidate it. Remaining fields cover every SQL parameter.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PackageReferenceReadKey {
    scope: [u8; 32],
    stage: (u64, u64),
    mount: u32,
    token: i64,
    ordinary_token: Option<u32>,
    domain: u32,
    lookup: u32,
}

pub(crate) fn unique_package_references_by_token(
    references: &[LoweredPackageReference],
) -> Result<Vec<LoweredPackageReference>> {
    let mut by_token = BTreeMap::new();
    for &reference in references {
        match by_token.entry(reference.token) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(reference);
            }
            std::collections::btree_map::Entry::Occupied(entry) => {
                let previous = entry.get();
                if (
                    previous.domain,
                    previous.root_scope,
                    previous.namespace,
                    previous.lookup,
                    previous.choice,
                ) != (
                    reference.domain,
                    reference.root_scope,
                    reference.namespace,
                    reference.lookup,
                    reference.choice,
                ) {
                    return Err(StoreError::corrupt(format!(
                        "package-reference token {} names conflicting rows: {previous:?} and {reference:?}",
                        reference.token
                    )));
                }
            }
        }
    }
    Ok(by_token.into_values().collect())
}

pub(in crate::analyzer::store) const STAGED_PACKAGE_REFERENCES: &str = r#"
SELECT p.token_key,p.domain_shared,p.reference_key,p.choice_key,p.source_site,p.root_scope_key,p.namespace,p.lookup_shared
FROM temp.selected_resolution_scope_mounts selected
JOIN temp.selected_resolution_stage_package_references p ON p.host_ordinal=selected.mount_ordinal
WHERE selected.mount_ordinal=?1
"#;

pub(in crate::analyzer::store) const ORDINARY_REFERENCES: &str = r#"
SELECT p.token_key,d.shared_identity,p.reference_key,p.choice_key,p.source_site,p.root_scope_key,p.namespace,l.shared_identity
FROM temp.selected_resolution_scope_mounts selected
JOIN temp.selected_resolution_mounts mounted ON mounted.mount_ordinal=selected.mount_ordinal
JOIN main.resolution_package_references p ON p.blob_id=mounted.blob_id
JOIN main.resolution_semantic_catalog d ON d.blob_id=p.blob_id AND d.local_key=p.domain_key
JOIN main.resolution_semantic_catalog l ON l.blob_id=p.blob_id AND l.local_key=p.lookup_key
WHERE selected.mount_ordinal=?1
"#;

const STAGED_REFERENCE_BY_SITE: &str = r#"
SELECT p.token_key,p.domain_shared,p.reference_key,p.choice_key,p.source_site,p.root_scope_key,p.namespace,p.lookup_shared
FROM temp.selected_resolution_scope_mounts selected
JOIN temp.selected_resolution_stage_package_references p ON p.host_ordinal=selected.mount_ordinal
WHERE selected.mount_ordinal=?1 AND p.reference_key=?2
"#;

const ORDINARY_REFERENCE_BY_SITE: &str = r#"
SELECT p.token_key,d.shared_identity,p.reference_key,p.choice_key,p.source_site,p.root_scope_key,p.namespace,l.shared_identity
FROM temp.selected_resolution_scope_mounts selected
JOIN temp.selected_resolution_mounts mounted ON mounted.mount_ordinal=selected.mount_ordinal
JOIN main.resolution_package_references p ON p.blob_id=mounted.blob_id AND p.reference_key=?2
JOIN main.resolution_semantic_catalog d ON d.blob_id=p.blob_id AND d.local_key=p.domain_key
JOIN main.resolution_semantic_catalog l ON l.blob_id=p.blob_id AND l.local_key=p.lookup_key
WHERE selected.mount_ordinal=?1
  AND NOT EXISTS (
    SELECT 1 FROM temp.selected_resolution_stage_package_references staged
    WHERE staged.host_ordinal=selected.mount_ordinal
      AND staged.reference_key=?3+p.reference_key
      AND staged.namespace=p.namespace
  )
"#;

const STAGED_REFERENCE_BY_TOKEN: &str = r#"
SELECT p.token_key,p.domain_shared,p.reference_key,p.choice_key,p.source_site,p.root_scope_key,p.namespace,p.lookup_shared
FROM temp.selected_resolution_scope_mounts selected
JOIN temp.selected_resolution_stage_package_references p ON p.host_ordinal=selected.mount_ordinal
WHERE selected.mount_ordinal=?1 AND p.token_key=?2
"#;

const ORDINARY_REFERENCE_BY_TOKEN: &str = r#"
SELECT p.token_key,d.shared_identity,p.reference_key,p.choice_key,p.source_site,p.root_scope_key,p.namespace,l.shared_identity
FROM temp.selected_resolution_scope_mounts selected
JOIN temp.selected_resolution_mounts mounted ON mounted.mount_ordinal=selected.mount_ordinal
JOIN main.resolution_package_references p ON p.blob_id=mounted.blob_id AND p.token_key=?2
JOIN main.resolution_semantic_catalog d ON d.blob_id=p.blob_id AND d.local_key=p.domain_key
JOIN main.resolution_semantic_catalog l ON l.blob_id=p.blob_id AND l.local_key=p.lookup_key
WHERE selected.mount_ordinal=?1
  AND NOT EXISTS (
    SELECT 1 FROM temp.selected_resolution_stage_package_references staged
    WHERE staged.host_ordinal=selected.mount_ordinal
      AND staged.reference_key=?3+p.reference_key
      AND staged.namespace=p.namespace
  )
"#;

const PACKAGE_REFERENCE_EXISTS: &str = r#"
SELECT EXISTS(
    SELECT 1
    FROM temp.selected_resolution_scope_mounts selected
    JOIN temp.selected_resolution_stage_package_references p
      ON p.host_ordinal=selected.mount_ordinal
    WHERE selected.mount_ordinal=?1
      AND p.token_key=?2
      AND p.domain_shared=?3
      AND p.lookup_shared=?4
    UNION ALL
    SELECT 1
    FROM temp.selected_resolution_scope_mounts selected
    JOIN temp.selected_resolution_mounts mounted
      ON mounted.mount_ordinal=selected.mount_ordinal
    JOIN main.resolution_semantic_catalog d
      ON d.blob_id=mounted.blob_id AND d.shared_identity=?5
    JOIN main.resolution_semantic_catalog l
      ON l.blob_id=mounted.blob_id AND l.shared_identity=?6
    JOIN main.resolution_package_references p
      ON p.blob_id=mounted.blob_id
     AND p.token_key=?7
     AND p.domain_key=d.local_key
     AND p.lookup_key=l.local_key
    WHERE selected.mount_ordinal=?1
      AND ?8 IS NOT NULL
      AND NOT EXISTS(
          SELECT 1
          FROM temp.selected_resolution_stage_package_references staged
          WHERE staged.host_ordinal=selected.mount_ordinal
            AND staged.reference_key=?9+p.reference_key
            AND staged.namespace=p.namespace
      )
    LIMIT 1
)
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

pub(in crate::analyzer::store) const STAGED_MEMBERS_BY_MOUNT: &str = r#"
SELECT p.token_key,p.domain_shared,p.definition_key,p.source_site,p.root_scope_key,p.namespace,p.lookup_shared
FROM temp.selected_resolution_scope_mounts selected
JOIN temp.selected_resolution_stage_package_members p ON p.host_ordinal=selected.mount_ordinal
WHERE selected.mount_ordinal=?1
"#;

pub(in crate::analyzer::store) const ORDINARY_MEMBERS_BY_MOUNT: &str = r#"
SELECT p.token_key,d.shared_identity,p.definition_key,p.source_site,p.root_scope_key,p.namespace,l.shared_identity
FROM temp.selected_resolution_scope_mounts selected
JOIN temp.selected_resolution_mounts mounted ON mounted.mount_ordinal=selected.mount_ordinal
JOIN main.resolution_package_members p ON p.blob_id=mounted.blob_id
JOIN main.resolution_semantic_catalog d ON d.blob_id=p.blob_id AND d.local_key=p.domain_key
JOIN main.resolution_semantic_catalog l ON l.blob_id=p.blob_id AND l.local_key=p.lookup_key
WHERE selected.mount_ordinal=?1
"#;

// A SQL row for this read only; both kinds use the same scalar column shape.
struct PackageCoordinates {
    token: SemanticId,
    domain: SemanticId,
    site_semantic: SemanticId,
    choice: Option<SemanticId>,
    source_site: ResolutionSiteId,
    root_scope: BindingNodeId,
    namespace: ResolutionNamespace,
    lookup: SemanticId,
}

// Package members have no precedence choice key, so keep their row shape
// separate from the package-reference projection.
struct PackageMemberCoordinates {
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
            choice: Some(codec::decode_semantic(row.get(3)?)),
            source_site: ResolutionSiteId::new(row.get(4)?),
            root_scope: codec::decode_node(row.get(5)?),
            namespace: ResolutionNamespace::from_label(&row.get::<_, String>(6)?)
                .ok_or_else(|| StoreError::corrupt("invalid package namespace"))?,
            lookup: codec::decode_semantic(-row.get::<_, i64>(7)?),
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
            choice: row
                .get::<_, Option<u32>>(3)?
                .map(|key| SemanticId::local(ordinal, key)),
            source_site: ResolutionSiteId::new(row.get(4)?),
            root_scope: BindingNodeId::local(ordinal, row.get(5)?),
            namespace: ResolutionNamespace::from_label(&row.get::<_, String>(6)?)
                .ok_or_else(|| StoreError::corrupt("invalid package namespace"))?,
            lookup: SemanticId::shared_name(
                names.from_persisted(SharedNameId::interned(row.get(7)?)),
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
            choice: self.choice,
            namespace: self.namespace,
            lookup: self.lookup,
        }
    }
}

impl PackageMemberCoordinates {
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
    pub(crate) fn has_package_reference(
        &self,
        mount: SelectedResolutionMountOrdinal,
        token: SemanticId,
        domain: SemanticId,
        lookup: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<SelectedPackageRows<bool>> {
        if cancellation.is_cancelled() {
            return Ok(SelectedPackageRows::Cancelled);
        }
        let (Some(domain), Some(lookup)) = (domain.shared_name_id(), lookup.shared_name_id())
        else {
            return Ok(SelectedPackageRows::Ready(false));
        };
        let ordinary_token = (token.ordinal() == Some(mount.get()))
            .then(|| token.local_key().expect("a local package reference token"));
        let key = PackageReferenceReadKey {
            scope: self.ready.inventory.scope_identity(),
            stage: self.ready.inventory.staged_read_epoch(),
            mount: mount.get(),
            token: codec::encode_semantic(token),
            ordinary_token,
            domain: domain.get(),
            lookup: lookup.get(),
        };
        let memo = &self.ready.package_reference_read_memo;
        if let Some(&present) = memo.borrow().get(&key) {
            return Ok(SelectedPackageRows::Ready(present));
        }
        let connection = self.ready.inventory.connection();
        let mut statement = connection.prepare_cached(PACKAGE_REFERENCE_EXISTS)?;
        let present = statement.query_row(
            rusqlite::params![
                mount.get(),
                key.token,
                key.domain,
                key.lookup,
                i64::from(key.domain),
                i64::from(key.lookup),
                key.ordinary_token,
                key.ordinary_token,
                codec::encode_semantic(SemanticId::local(mount.get(), 0)),
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if cancellation.is_cancelled() {
            return Ok(SelectedPackageRows::Cancelled);
        }
        memo.borrow_mut().insert(key, present);
        Ok(SelectedPackageRows::Ready(present))
    }

    #[doc(hidden)]
    pub fn selected_package_references(
        &self,
        mount: SelectedResolutionMountOrdinal,
        cancellation: &CancellationToken,
    ) -> Result<SelectedPackageRows<Vec<LoweredPackageReference>>> {
        let connection = self.ready.inventory.connection();
        let names = self.ready.shared_names();
        let mut result = BTreeMap::new();
        if !self
            .ready
            .inventory
            .stage_family_is_empty(StageFamily::PackageReferences)?
        {
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

    pub(crate) fn selected_package_reference_for_site(
        &self,
        mount: SelectedResolutionMountOrdinal,
        reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<SelectedPackageRows<Vec<LoweredPackageReference>>> {
        if cancellation.is_cancelled() {
            return Ok(SelectedPackageRows::Cancelled);
        }
        self.selected_package_reference_rows(
            mount,
            reference,
            STAGED_REFERENCE_BY_SITE,
            ORDINARY_REFERENCE_BY_SITE,
            cancellation,
        )
    }

    pub(crate) fn selected_package_reference_for_token(
        &self,
        mount: SelectedResolutionMountOrdinal,
        token: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<SelectedPackageRows<Vec<LoweredPackageReference>>> {
        self.selected_package_reference_rows(
            mount,
            token,
            STAGED_REFERENCE_BY_TOKEN,
            ORDINARY_REFERENCE_BY_TOKEN,
            cancellation,
        )
    }

    // Both readers preserve staged replacement by reference/namespace while
    // seeking only the source identity already established by the demand.
    fn selected_package_reference_rows(
        &self,
        mount: SelectedResolutionMountOrdinal,
        reference: SemanticId,
        staged_sql: &str,
        ordinary_sql: &str,
        cancellation: &CancellationToken,
    ) -> Result<SelectedPackageRows<Vec<LoweredPackageReference>>> {
        if cancellation.is_cancelled() {
            return Ok(SelectedPackageRows::Cancelled);
        }
        let local_key = reference
            .local_key()
            .filter(|_| reference.ordinal() == Some(mount.get()));
        let staged_key = codec::encode_semantic(reference);
        let local_base = codec::encode_semantic(SemanticId::local(mount.get(), 0));
        let connection = self.ready.inventory.connection();
        let names = self.ready.shared_names();
        let mut result = BTreeMap::new();
        if !self
            .ready
            .inventory
            .stage_family_is_empty(StageFamily::PackageReferences)?
        {
            let mut statement = connection.prepare_cached(staged_sql)?;
            let mut rows = statement.query(rusqlite::params![mount.get(), staged_key])?;
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(SelectedPackageRows::Cancelled);
                }
                let fact = PackageCoordinates::staged(row)?.reference();
                if result
                    .insert((fact.reference, fact.namespace), fact)
                    .is_some_and(|previous| previous != fact)
                {
                    return Err(StoreError::corrupt(
                        "contradictory staged package references",
                    ));
                }
            }
        }
        {
            let mut statement = connection.prepare_cached(ordinary_sql)?;
            let mut rows =
                statement.query(rusqlite::params![mount.get(), local_key, local_base])?;
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(SelectedPackageRows::Cancelled);
                }
                let fact = PackageCoordinates::ordinary(row, mount.get(), &names)?.reference();
                result
                    .entry((fact.reference, fact.namespace))
                    .or_insert(fact);
            }
        }
        Ok(SelectedPackageRows::Ready(result.into_values().collect()))
    }

    #[doc(hidden)]
    pub fn selected_package_members_for_lookup(
        &self,
        mount: SelectedResolutionMountOrdinal,
        lookup: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<SelectedPackageRows<Vec<LoweredPackageMember>>> {
        let shared = lookup
            .shared_name_id()
            .expect("package lookup is a shared name");
        let connection = self.ready.inventory.connection();
        let names = self.ready.shared_names();
        let mut result = BTreeMap::new();
        if !self
            .ready
            .inventory
            .stage_family_is_empty(StageFamily::PackageMembers)?
        {
            let mut statement = connection.prepare_cached(STAGED_MEMBERS)?;
            let mut rows = statement.query(rusqlite::params![mount.get(), shared.get()])?;
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(SelectedPackageRows::Cancelled);
                }
                let fact = PackageMemberCoordinates::staged(row)?.member();
                let key = (fact.definition, fact.namespace);
                if result
                    .insert(key, fact)
                    .is_some_and(|previous| previous != fact)
                {
                    return Err(StoreError::corrupt("contradictory staged package members"));
                }
            }
        }
        if let Some(stored) = names.to_persisted(shared) {
            let mut statement = connection.prepare_cached(ORDINARY_MEMBERS)?;
            let mut rows = statement.query(rusqlite::params![mount.get(), stored.get()])?;
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(SelectedPackageRows::Cancelled);
                }
                let fact = PackageMemberCoordinates::ordinary(row, mount.get(), &names)?.member();
                // A staged row for this identity wins even when it changed the
                // lookup name and therefore was absent from the lookup query.
                let mut authority = None;
                if !self
                    .ready
                    .inventory
                    .stage_family_is_globally_empty(StageFamily::PackageMembers)?
                {
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
                    while let Some(row) = staged.next()? {
                        if cancellation.is_cancelled() {
                            return Ok(SelectedPackageRows::Cancelled);
                        }
                        let staged_fact = PackageMemberCoordinates::staged(row)?.member();
                        if authority.is_some_and(|prior| prior != staged_fact) {
                            return Err(StoreError::corrupt(
                                "contradictory staged package members",
                            ));
                        }
                        authority = Some(staged_fact);
                    }
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

    /// Read one mount's package members in two bounded passes, applying staged
    /// overlay authority by definition and namespace before grouping by lookup.
    #[doc(hidden)]
    pub fn selected_package_members_by_lookup(
        &self,
        mount: SelectedResolutionMountOrdinal,
        cancellation: &CancellationToken,
    ) -> Result<SelectedPackageRows<HashMap<SemanticId, Vec<LoweredPackageMember>>>> {
        let connection = self.ready.inventory.connection();
        let names = self.ready.shared_names();
        let mut by_identity = BTreeMap::new();
        if !self
            .ready
            .inventory
            .stage_family_is_empty(StageFamily::PackageMembers)?
        {
            let mut statement = connection.prepare_cached(STAGED_MEMBERS_BY_MOUNT)?;
            let mut rows = statement.query([mount.get()])?;
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(SelectedPackageRows::Cancelled);
                }
                let member = PackageMemberCoordinates::staged(row)?.member();
                let key = (member.definition, member.namespace);
                if by_identity
                    .insert(key, member)
                    .is_some_and(|previous| previous != member)
                {
                    return Err(StoreError::corrupt("contradictory staged package members"));
                }
            }
        }
        let mut statement = connection.prepare_cached(ORDINARY_MEMBERS_BY_MOUNT)?;
        let mut rows = statement.query([mount.get()])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(SelectedPackageRows::Cancelled);
            }
            let member = PackageMemberCoordinates::ordinary(row, mount.get(), &names)?.member();
            by_identity
                .entry((member.definition, member.namespace))
                .or_insert(member);
        }
        if cancellation.is_cancelled() {
            return Ok(SelectedPackageRows::Cancelled);
        }
        let mut by_lookup = HashMap::default();
        for member in by_identity.into_values() {
            if cancellation.is_cancelled() {
                return Ok(SelectedPackageRows::Cancelled);
            }
            by_lookup
                .entry(member.lookup)
                .or_insert_with(Vec::new)
                .push(member);
        }
        if cancellation.is_cancelled() {
            return Ok(SelectedPackageRows::Cancelled);
        }
        Ok(SelectedPackageRows::Ready(by_lookup))
    }
}
