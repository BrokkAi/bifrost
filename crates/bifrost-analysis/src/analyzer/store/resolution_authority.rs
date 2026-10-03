//! Ordinary resolution authority read by requested keys from persisted rows.

use super::resolution_prepare::authority_rows;
use super::resolution_selection::SelectedResolutionMountRecord;
use super::{Result as StoreResult, StoreError};
use crate::CancellationToken;
use crate::analyzer::resolution::{
    BindingNodeId, PartialPathId, ResolutionLocalKey, ResolutionLookupSemanticRecipe,
    ResolutionNodeIdentity, ResolutionSemanticIdentity, SelectedNodeProvenance,
    SelectedResolutionMount, SelectedResolutionMountOrdinal, SelectedSemanticLocator,
    SelectedSemanticProvenance, SemanticId, SharedNameId, SharedNameInterner,
};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_core::analyzer::resolution_facts::{
    BindingProjectionKind, ResolutionMemberKind, ResolutionNamespace, ResolutionScopeId,
    ResolutionSiteId, ResolutionTypeTransferKind,
};
use brokk_bifrost_core::analyzer::structural::resolution::ResolutionGapOriginKind;
use rusqlite::{Connection, OptionalExtension};

#[derive(Clone, Debug)]
pub(crate) struct RootExportHalf {
    pub(crate) recipe: ResolutionLookupSemanticRecipe,
    /// The reverse route admits only the canonical two-symbol export half:
    /// two fixed start symbols, no fixed end symbol, and one open tail shared
    /// by both endpoints.
    pub(crate) canonical_export_shape: bool,
}

/// The mounts whose publication one crate stage has already checked, by
/// ordinal and blob.
///
/// `read_authority` checks the mount's publication (READ_AUTHORITY) before
/// every keyed read. On the whole tract graph that was 7.86 M checks, 22.8
/// per reference, against a few hundred mounts per stage. Within a crate
/// stage the check runs once per mount; a later read of the same mount
/// relies on it.
///
/// Contract: a publication that changes after the stage checked it is no
/// longer caught by the next read of that mount. The graph build's
/// `finish_native` revalidates the whole selection, so such a change ends the
/// request `Stale` at the end instead of at the next read. The caller gets
/// the same answer. Outside a crate stage the set is `None` and every read
/// checks, as before.
///
/// The stage also keeps each semantic catalog provenance answer
/// (SEMANTIC_PROVENANCE) by blob and local key. On the whole tract graph the
/// statement ran 5.10 M times, and 78% of them repeated a key the same stage
/// had already asked (tract_core: 881,634 for 193,074 keys). A catalog row
/// is persisted content of the blob and does not change while the stage's
/// checked publication stands.
#[derive(Default)]
pub(crate) struct AuthorityValidations {
    mounts: HashSet<(SelectedResolutionMountOrdinal, i64)>,
    semantic_identities: HashMap<(i64, u32), Option<[u8; 32]>>,
}

pub(crate) struct SelectedResolutionAuthority<'project> {
    connection: &'project Connection,
    names: &'project super::resolution::SharedNameTable,
    requested_mounts: &'project super::resolution_selection::RequestedResolutionMountRows,
    persisted_mount_count: usize,
    validated: &'project std::cell::RefCell<Option<AuthorityValidations>>,
}

impl<'project> SelectedResolutionAuthority<'project> {
    pub(crate) fn new(
        connection: &'project Connection,
        names: &'project super::resolution::SharedNameTable,
        requested_mounts: &'project super::resolution_selection::RequestedResolutionMountRows,
        persisted_mount_count: usize,
        validated: &'project std::cell::RefCell<Option<AuthorityValidations>>,
    ) -> Self {
        Self {
            connection,
            names,
            requested_mounts,
            persisted_mount_count,
            validated,
        }
    }

    pub(crate) fn intern_shared_name_digest(
        &self,
        digest: [u8; 32],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<SemanticId>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        super::resolution::with_resolution_read_progress_handler(
            self.connection,
            cancellation,
            |connection| {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let identity = self.names.interner(connection).intern(digest);
                Ok(Some(SemanticId::shared_name(identity)))
            },
        )
    }

    fn mount_record(
        &self,
        ordinal: crate::analyzer::resolution::SelectedResolutionMountOrdinal,
    ) -> StoreResult<Option<std::sync::Arc<SelectedResolutionMountRecord>>> {
        if ordinal.get() as usize >= self.persisted_mount_count {
            return Ok(None);
        }
        self.requested_mounts.by_ordinal(self.connection, ordinal)
    }

    /// The mount and blob-local key of an ordinary gap reason, or `None` when
    /// it is a stage reason or names no persisted mount.
    ///
    /// A reason has no catalog row, so its key range classifies it.
    pub(crate) fn ordinary_gap_reason(
        &self,
        reason: SemanticId,
    ) -> StoreResult<
        Option<(
            crate::analyzer::resolution::SelectedResolutionMountOrdinal,
            u32,
        )>,
    > {
        assert!(
            reason.shared_name_id().is_none(),
            "a gap reason is never a shared name: {reason:?}"
        );
        let (Some(ordinal), Some(key)) = (reason.ordinal(), reason.local_key()) else {
            return Ok(None);
        };
        if !super::resolution_stage::allocation::is_ordinary_key(key) {
            return Ok(None);
        }
        let ordinal = SelectedResolutionMountOrdinal::new(ordinal);
        Ok(self.mount_record(ordinal)?.map(|_| (ordinal, key)))
    }

    /// Genuine ordinary catalog authority, excluding supplemental registrations.
    /// Outer None is cancellation; inner None means no ordinary catalog row.
    pub(crate) fn semantic_catalog_provenance(
        &self,
        semantic: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Option<SelectedSemanticProvenance>>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(key) = semantic.local_key() else {
            return Ok(Some(None));
        };
        let Some(ordinal) = semantic.ordinal() else {
            return Ok(Some(None));
        };
        let Some(record) = self.mount_record(SelectedResolutionMountOrdinal::new(ordinal))? else {
            return Ok(Some(None));
        };
        let mount = SelectedResolutionMount::from_ordinal(record.ordinal());
        let provenance = |digest: Option<[u8; 32]>| {
            digest.map(|digest| {
                SelectedSemanticProvenance::fragment_local(
                    mount,
                    ResolutionLocalKey::new(i64::from(key)),
                    ResolutionSemanticIdentity::fragment_local(digest),
                )
            })
        };
        let remembered = self.validated.borrow().as_ref().and_then(|validated| {
            validated
                .semantic_identities
                .get(&(record.blob_id(), key))
                .copied()
        });
        if let Some(digest) = remembered {
            return Ok(Some(provenance(digest)));
        }
        self.read_authority(&record, cancellation, |conn| {
            let digest = conn
                .prepare_cached(authority_rows::SEMANTIC_PROVENANCE_SQL)?
                .query_row(rusqlite::params![record.blob_id(), key], |row| {
                    row.get::<_, [u8; 32]>(0)
                })
                .optional()?;
            if let Some(validated) = self.validated.borrow_mut().as_mut() {
                validated
                    .semantic_identities
                    .insert((record.blob_id(), key), digest);
            }
            Ok(provenance(digest))
        })
    }

    /// Genuine ordinary node authority; context boundaries are not catalog rows.
    pub(crate) fn node_catalog_provenance(
        &self,
        node: BindingNodeId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Option<SelectedNodeProvenance>>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(key) = node.local_key() else {
            return Ok(Some(None));
        };
        let Some(ordinal) = node.ordinal() else {
            return Ok(Some(None));
        };
        let Some(record) = self.mount_record(SelectedResolutionMountOrdinal::new(ordinal))? else {
            return Ok(Some(None));
        };
        let mount = SelectedResolutionMount::from_ordinal(record.ordinal());
        self.read_authority(&record, cancellation, |conn| {
            let identity = conn
                .prepare_cached(authority_rows::NODE_PROVENANCE_SQL)?
                .query_row(rusqlite::params![record.blob_id(), key], |row| {
                    row.get::<_, [u8; 32]>(0)
                })
                .optional()?;
            Ok(identity.map(|digest| {
                SelectedNodeProvenance::fragment_local(
                    mount,
                    ResolutionLocalKey::new(i64::from(key)),
                    ResolutionNodeIdentity::new(digest),
                )
            }))
        })
    }

    pub(crate) fn semantic_sites(
        &self,
        mount: &SelectedResolutionMountRecord,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(SemanticId, BindingNodeId, ResolutionNamespace)>>> {
        use super::resolution_prepare::resolution_rows::{namespace_from_code, semantic_role_code};
        self.read_authority(mount, cancellation, |conn| {
            let (sql, first, second) = if let Some(site) = locator.source_site() {
                (authority_rows::SEMANTIC_SITES_SQL, i64::from(site.get()), 0)
            } else if let Some((start, end)) = locator.reference_range() {
                (
                    authority_rows::SEMANTIC_SITES_2_SQL,
                    start as i64,
                    end as i64,
                )
            } else {
                let (start, end) = locator
                    .declaration_range()
                    .expect("structured locator address");
                (
                    authority_rows::SEMANTIC_SITES_3_SQL,
                    start as i64,
                    end as i64,
                )
            };
            Ok(conn
                .prepare_cached(sql)?
                .query_map(
                    rusqlite::params![
                        mount.blob_id(),
                        first,
                        second,
                        semantic_role_code(locator.role())
                    ],
                    |row| {
                        let key: u32 = row.get(0)?;
                        Ok((
                            SemanticId::local(mount.ordinal().get(), key),
                            BindingNodeId::local(mount.ordinal().get(), key),
                            namespace_from_code(row.get(1)?),
                        ))
                    },
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    /// Only returned catalog rows carry authority; absence differs from a
    /// present catalog row whose source scope is NULL.
    #[allow(clippy::type_complexity)] // One query returns node identity and optional source scope.
    pub(crate) fn scope_catalog_nodes(
        &self,
        mount: &SelectedResolutionMountRecord,
        keys: &[u32],
        cancellation: &CancellationToken,
    ) -> StoreResult<
        Option<HashMap<BindingNodeId, (ResolutionNodeIdentity, Option<ResolutionScopeId>)>>,
    > {
        self.read_authority(mount, cancellation, |conn| {
            let mut result = HashMap::default();
            let mut statement = conn.prepare_cached(authority_rows::SCOPE_ORDINALS_SQL)?;
            let mut rows = statement.query(rusqlite::params![
                mount.blob_id(),
                serde_json::to_string(keys).expect("scalar node keys"),
            ])?;
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    break;
                }
                let key: u32 = row.get(0)?;
                let scope: Option<u32> = row.get(1)?;
                let identity = ResolutionNodeIdentity::new(row.get(2)?);
                result.insert(
                    BindingNodeId::local(mount.ordinal().get(), key),
                    (identity, scope.map(ResolutionScopeId::new)),
                );
            }
            Ok(result)
        })
    }

    /// The runtime semantic one selected mount gives a producer identity.
    ///
    /// A mounted id was a pure function of the identity and the fragment, so
    /// anything holding an identity could state the id without opening
    /// anything. A local id is a catalog position now, so only the mount's own
    /// catalog can, and this is the read that replaces the computation. The
    /// ordinary catalog supplies only its own authority; stage rows are composed
    /// by the caller and never stand in for a persisted catalog entry.
    ///
    /// The inner `None` says this mount's catalog does not hold the identity.
    /// The outer `None` reports cancellation; stale publication is an error.
    pub(crate) fn semantic_for_identity(
        &self,
        mount: &SelectedResolutionMountRecord,
        identity: ResolutionSemanticIdentity,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Option<SemanticId>>> {
        self.read_authority(mount, cancellation, |conn| {
            let key = match identity {
                ResolutionSemanticIdentity::FragmentLocal(digest) => conn
                    .prepare_cached(authority_rows::SEMANTIC_FOR_IDENTITY_SQL)?
                    .query_row(
                        rusqlite::params![mount.blob_id(), digest.as_slice()],
                        |row| row.get::<_, u32>(0),
                    )
                    .optional()?,
                ResolutionSemanticIdentity::GapReason(_) => {
                    panic!("a gap reason has no catalog row to look up: {identity:?}")
                }
                ResolutionSemanticIdentity::Shared(name) => {
                    use crate::analyzer::resolution::SharedNameInterner;
                    let names = self.names.interner(conn);
                    let Some(stored) = names.to_persisted(name) else {
                        return Ok(None);
                    };
                    return Ok(conn
                        .prepare_cached(authority_rows::SEMANTIC_FOR_IDENTITY_2_SQL)?
                        .query_row(rusqlite::params![mount.blob_id(), stored.get()], |row| {
                            row.get::<_, i64>(0)
                        })
                        .optional()?
                        .map(|id| {
                            SemanticId::shared_name(
                                names.from_persisted(SharedNameId::interned(id)),
                            )
                        }));
                }
            };
            Ok(key.map(|key| SemanticId::local(mount.ordinal().get(), key)))
        })
    }

    pub(crate) fn semantics_for_identities(
        &self,
        mount: &SelectedResolutionMountRecord,
        digests: &[String],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(usize, SemanticId)>>> {
        self.read_authority(mount, cancellation, |conn| {
            Ok(conn
                .prepare_cached(authority_rows::SEMANTICS_FOR_IDENTITIES_SQL)?
                .query_map(
                    rusqlite::params![
                        mount.blob_id(),
                        serde_json::to_string(digests).expect("scalar digests")
                    ],
                    |row| {
                        Ok((
                            row.get(0)?,
                            SemanticId::local(mount.ordinal().get(), row.get(1)?),
                        ))
                    },
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    /// The runtime node one selected mount gives a producer identity. See
    /// [`Self::semantic_for_identity`].
    pub(crate) fn node_for_identity(
        &self,
        mount: &SelectedResolutionMountRecord,
        identity: ResolutionNodeIdentity,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Option<BindingNodeId>>> {
        self.read_authority(mount, cancellation, |conn| {
            Ok(conn
                .prepare_cached(authority_rows::NODE_FOR_IDENTITY_SQL)?
                .query_row(
                    rusqlite::params![mount.blob_id(), identity.digest().as_slice()],
                    |row| row.get::<_, u32>(0),
                )
                .optional()?
                .map(|key| BindingNodeId::local(mount.ordinal().get(), key)))
        })
    }

    /// Paths beginning at one source scope in the selected blob.
    pub(crate) fn scope_start_paths(
        &self,
        mount: &SelectedResolutionMountRecord,
        scope: ResolutionScopeId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<PartialPathId>>> {
        self.read_authority(mount, cancellation, |conn| {
            Ok(conn
                .prepare_cached(authority_rows::SCOPE_START_PATHS_SQL)?
                .query_map(rusqlite::params![mount.blob_id(), scope.get()], |row| {
                    Ok(PartialPathId::local(mount.ordinal().get(), row.get(0)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    pub(crate) fn reference_lookup_spellings(
        &self,
        mount: &SelectedResolutionMountRecord,
        keys: &[u32],
        namespace: ResolutionNamespace,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<HashMap<SemanticId, String>>> {
        self.read_authority(mount, cancellation, |conn| {
            let mut statement =
                conn.prepare_cached(authority_rows::REFERENCE_LOOKUP_SPELLING_SQL)?;
            let rows = statement.query_map(
                rusqlite::params![
                    mount.blob_id(),
                    serde_json::to_string(keys).expect("scalar local key array"),
                    super::resolution_prepare::resolution_rows::namespace_code(namespace)
                ],
                |row| Ok((row.get::<_, u32>(0)?, row.get::<_, String>(1)?)),
            )?;
            let mut spellings = HashMap::default();
            for row in rows {
                let (key, spelling) = row?;
                let reference = SemanticId::local(mount.ordinal().get(), key);
                if let Some(previous) = spellings.insert(reference, spelling.clone()) {
                    assert_eq!(
                        previous, spelling,
                        "a native reference has one lookup name per namespace"
                    );
                }
            }
            Ok(spellings)
        })
    }

    pub(crate) fn definition_source_site(
        &self,
        mount: &SelectedResolutionMountRecord,
        definition: BindingNodeId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Option<ResolutionSiteId>>> {
        self.read_authority(mount, cancellation, |conn| {
            if definition.ordinal() != Some(mount.ordinal().get()) {
                return Ok(None);
            }
            Ok(conn
                .prepare_cached(authority_rows::DEFINITION_SOURCE_SITE_SQL)?
                .query_row(
                    rusqlite::params![
                        mount.blob_id(),
                        definition.local_key().expect("local definition")
                    ],
                    |row| Ok(ResolutionSiteId::new(row.get(0)?)),
                )
                .optional()?)
        })
    }

    pub(crate) fn root_export_halves(
        &self,
        mount: &SelectedResolutionMountRecord,
        site: ResolutionSiteId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<RootExportHalf>>> {
        self.read_authority(mount, cancellation, |conn| {
            Ok(conn
                .prepare_cached(authority_rows::ROOT_EXPORT_HALVES_SQL)?
                .query_map(rusqlite::params![mount.blob_id(), site.get()], |row| {
                    Ok(RootExportHalf {
                        recipe: super::resolution_prepare::resolution_rows::decode_lookup_recipe(
                            row.get(0)?,
                            row.get(1)?,
                            &row.get::<_, String>(2)?,
                        ),
                        canonical_export_shape: row.get::<_, Option<bool>>(3)?.unwrap_or(false),
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    pub(crate) fn lookup_recipes(
        &self,
        mount: &SelectedResolutionMountRecord,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<ResolutionLookupSemanticRecipe>>> {
        self.read_authority(mount, cancellation, |conn| {
            Ok(conn
                .prepare_cached(authority_rows::LOOKUP_RECIPES_SQL)?
                .query_map([mount.blob_id()], |row| {
                    Ok(
                        super::resolution_prepare::resolution_rows::decode_lookup_recipe(
                            row.get(0)?,
                            row.get(1)?,
                            &row.get::<_, String>(2)?,
                        ),
                    )
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    pub(crate) fn unsupported_gap_reasons(
        &self,
        mount: &SelectedResolutionMountRecord,
        site: ResolutionSiteId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<SemanticId>>> {
        use super::resolution_prepare::resolution_rows::gap_origin_code;
        use crate::analyzer::resolution::LoweringGapOrigin;
        self.read_authority(mount, cancellation, |conn| {
            Ok(conn
                .prepare_cached(authority_rows::UNSUPPORTED_GAP_REASONS_SQL)?
                .query_map(
                    rusqlite::params![
                        mount.blob_id(),
                        site.get(),
                        gap_origin_code(LoweringGapOrigin::from_kind(
                            ResolutionGapOriginKind::UnsupportedScopeOrBinder
                        )),
                        gap_origin_code(LoweringGapOrigin::from_kind(
                            ResolutionGapOriginKind::UnsupportedExpression
                        )),
                        gap_origin_code(LoweringGapOrigin::from_kind(
                            ResolutionGapOriginKind::UnexpandedItemMacro
                        ))
                    ],
                    |row| Ok(SemanticId::local(mount.ordinal().get(), row.get(0)?)),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    pub(crate) fn lookup_reference_sites(
        &self,
        mount: &SelectedResolutionMountRecord,
        lookup: SemanticId,
        binder_scope: Option<ResolutionScopeId>,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<ResolutionSiteId>>> {
        self.read_authority(mount, cancellation, |conn| {
            let (shared, key) = match lookup.shared_name_id() {
                Some(name) => {
                    let Some(stored) = self.names.interner(conn).to_persisted(name) else {
                        return Ok(Vec::new());
                    };
                    (true, i64::from(stored.get()))
                }
                None if lookup.ordinal() == Some(mount.ordinal().get()) => {
                    (false, i64::from(lookup.local_key().expect("local lookup")))
                }
                None => return Ok(Vec::new()),
            };
            let (sql, scope) = match binder_scope {
                None => (
                    if shared {
                        authority_rows::LOOKUP_REFERENCE_SHARED_SQL
                    } else {
                        authority_rows::LOOKUP_REFERENCE_LOCAL_SQL
                    },
                    None,
                ),
                Some(scope) => (
                    if shared {
                        authority_rows::SCOPED_LOOKUP_REFERENCE_SHARED_SQL
                    } else {
                        authority_rows::SCOPED_LOOKUP_REFERENCE_LOCAL_SQL
                    },
                    Some(scope.get()),
                ),
            };
            Ok(conn
                .prepare_cached(sql)?
                .query_map(rusqlite::params![mount.blob_id(), key, scope], |row| {
                    Ok(ResolutionSiteId::new(row.get(0)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    pub(crate) fn root_demand_reference_sites(
        &self,
        mount: &SelectedResolutionMountRecord,
        terminal: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<ResolutionSiteId>>> {
        Ok(self
            .root_demand_rows(mount, terminal, cancellation)?
            .map(|rows| rows.into_iter().map(|(site, _)| site).collect()))
    }

    pub(crate) fn imported_root_demand_reference_sites(
        &self,
        mount: &SelectedResolutionMountRecord,
        terminal: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<ResolutionSiteId>>> {
        self.read_authority(mount, cancellation, |conn| {
            let Some(name) = terminal.shared_name_id() else {
                return Ok(Vec::new());
            };
            let Some(stored) = self.names.interner(conn).to_persisted(name) else {
                return Ok(Vec::new());
            };
            Ok(conn
                .prepare_cached(authority_rows::IMPORTED_ROOT_DEMAND_SHARED_SQL)?
                .query_map(rusqlite::params![mount.blob_id(), stored.get()], |row| {
                    Ok(ResolutionSiteId::new(row.get(0)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    pub(crate) fn prefixed_root_demand_reference_sites(
        &self,
        mount: &SelectedResolutionMountRecord,
        terminal: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<ResolutionSiteId>>> {
        Ok(self
            .root_demand_rows(mount, terminal, cancellation)?
            .map(|rows| {
                rows.into_iter()
                    .filter_map(|(site, prefixed)| prefixed.then_some(site))
                    .collect()
            }))
    }

    fn root_demand_rows(
        &self,
        mount: &SelectedResolutionMountRecord,
        terminal: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(ResolutionSiteId, bool)>>> {
        self.read_authority(mount, cancellation, |conn| {
            let (sql, key) = match terminal.shared_name_id() {
                Some(name) => {
                    let Some(stored) = self.names.interner(conn).to_persisted(name) else {
                        return Ok(Vec::new());
                    };
                    (
                        authority_rows::ROOT_DEMAND_SHARED_SQL,
                        i64::from(stored.get()),
                    )
                }
                None if terminal.ordinal() == Some(mount.ordinal().get()) => (
                    authority_rows::ROOT_DEMAND_LOCAL_SQL,
                    i64::from(terminal.local_key().expect("local terminal")),
                ),
                None => return Ok(Vec::new()),
            };
            Ok(conn
                .prepare_cached(sql)?
                .query_map(rusqlite::params![mount.blob_id(), key], |row| {
                    Ok((ResolutionSiteId::new(row.get(0)?), row.get(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    pub(crate) fn type_identity_observation_sites(
        &self,
        mount: &SelectedResolutionMountRecord,
        site: ResolutionSiteId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<ResolutionSiteId>>> {
        use super::resolution_prepare::resolution_rows::code;
        use brokk_bifrost_core::analyzer::resolution_facts::{
            ALL_BINDING_PROJECTION_KINDS, ALL_RESOLUTION_TYPE_TRANSFER_KINDS,
        };
        self.read_authority(mount, cancellation, |conn| {
            let mut reached = HashSet::default();
            let mut pending = Vec::new();
            let mut projections =
                conn.prepare_cached(authority_rows::TYPE_IDENTITY_OBSERVATION_SITES_SQL)?;
            for slot in projections.query_map(
                rusqlite::params![
                    mount.blob_id(),
                    site.get(),
                    code(
                        ALL_BINDING_PROJECTION_KINDS,
                        BindingProjectionKind::TargetTypeIdentity
                    ),
                    code(
                        ALL_BINDING_PROJECTION_KINDS,
                        BindingProjectionKind::TargetNominalTypeIdentity
                    )
                ],
                |row| row.get::<_, u32>(0),
            )? {
                let slot = slot?;
                if reached.insert(slot) {
                    pending.push(slot);
                }
            }
            let mut observation =
                conn.prepare_cached(authority_rows::TYPE_IDENTITY_OBSERVATION_SITES_2_SQL)?;
            let mut transfers =
                conn.prepare_cached(authority_rows::TYPE_IDENTITY_OBSERVATION_SITES_3_SQL)?;
            let mut sites = Vec::new();
            while let Some(slot) = pending.pop() {
                if cancellation.is_cancelled() {
                    break;
                }
                if let Some(site) = observation
                    .query_row(rusqlite::params![mount.blob_id(), slot], |row| {
                        row.get::<_, u32>(0)
                    })
                    .optional()?
                {
                    sites.push(ResolutionSiteId::new(site));
                }
                for target in transfers.query_map(
                    rusqlite::params![
                        mount.blob_id(),
                        slot,
                        code(
                            ALL_RESOLUTION_TYPE_TRANSFER_KINDS,
                            ResolutionTypeTransferKind::TypeIdentity
                        )
                    ],
                    |row| row.get::<_, u32>(0),
                )? {
                    let target = target?;
                    if reached.insert(target) {
                        pending.push(target);
                    }
                }
            }
            Ok(sites)
        })
    }

    pub(crate) fn contract_reference_sites(
        &self,
        mount: &SelectedResolutionMountRecord,
        definition: SemanticId,
        kind: ResolutionMemberKind,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<ResolutionSiteId>>> {
        self.read_authority(mount, cancellation, |conn| {
            if definition.ordinal() != Some(mount.ordinal().get()) {
                return Ok(Vec::new());
            }
            let mut statement =
                conn.prepare_cached(authority_rows::CONTRACT_REFERENCE_SITES_SQL)?;
            Ok(statement
                .query_map(
                    rusqlite::params![
                        mount.blob_id(),
                        definition
                            .local_key()
                            .expect("contract definition is local"),
                        super::resolution_prepare::resolution_rows::code(brokk_bifrost_core::analyzer::resolution_facts::ALL_RESOLUTION_MEMBER_KINDS, kind)
                    ],
                    |row| Ok(ResolutionSiteId::new(row.get(0)?)),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    pub(crate) fn qualified_route_reference_sites(
        &self,
        mount: &SelectedResolutionMountRecord,
        lookup: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<ResolutionSiteId>>> {
        self.read_authority(mount, cancellation, |conn| {
            let Some(name) = lookup.shared_name_id() else {
                return Ok(Vec::new());
            };
            let Some(stored) = self.names.interner(conn).to_persisted(name) else {
                return Ok(Vec::new());
            };
            Ok(conn
                .prepare_cached(authority_rows::QUALIFIED_ROUTE_REFERENCE_SITES_SQL)?
                .query_map(rusqlite::params![mount.blob_id(), stored.get()], |row| {
                    Ok(ResolutionSiteId::new(row.get(0)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    /// Validate the selected publication before answering keyed authority queries.
    pub(crate) fn ensure_authority(
        &self,
        mount: &SelectedResolutionMountRecord,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<()>> {
        self.read_authority(mount, cancellation, |_| Ok(()))
    }

    fn read_authority<T>(
        &self,
        mount: &SelectedResolutionMountRecord,
        cancellation: &CancellationToken,
        read: impl FnOnce(&Connection) -> StoreResult<T>,
    ) -> StoreResult<Option<T>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let result = super::resolution::with_resolution_read_progress_handler(
            self.connection,
            cancellation,
            |conn| {
                let key = (mount.ordinal(), mount.blob_id());
                if self
                    .validated
                    .borrow()
                    .as_ref()
                    .is_some_and(|validated| validated.mounts.contains(&key))
                {
                    return read(conn);
                }
                let ready = conn
                    .prepare_cached(authority_rows::READ_AUTHORITY_SQL)?
                    .query_row(
                        rusqlite::params![
                            mount.blob_id(),
                            mount.storage_language(),
                            mount.semantic_language().config_label(),
                            mount.producer_epoch(),
                            mount.interior_digest().as_slice()
                        ],
                        |_| Ok(()),
                    )
                    .optional()?;
                if ready.is_none() {
                    return Err(StoreError::stale_resolution(
                        "selected catalog authority changed",
                    ));
                }
                if let Some(validated) = self.validated.borrow_mut().as_mut() {
                    validated.mounts.insert(key);
                }
                read(conn)
            },
        );
        match result {
            Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => Ok(None),
            Err(error) => Err(error),
            Ok(_) if cancellation.is_cancelled() => Ok(None),
            Ok(value) => Ok(Some(value)),
        }
    }
}
