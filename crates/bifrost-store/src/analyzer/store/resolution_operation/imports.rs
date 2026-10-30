//! Indexed, blob-local import syntax. Results live only for the current request.
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use std::hash::Hash;
use std::sync::Arc;

use super::super::selected_read_memo::ExactReadMemo;
use super::{
    FactPageVisitor, ReadySelectedResolution, SelectedResolutionMountOrdinal,
    SelectedResolutionOperation,
};
use crate::CancellationToken;
use crate::analyzer::resolution::ResolutionQuery;
use crate::analyzer::resolution::SemanticId;
use crate::analyzer::resolution::{
    BatchResolutionFragmentSource, BindingFragmentId, BindingNodeId, CandidatePathIdentity,
    ResolutionLookupSemanticRecipe, SelectedRootPathHalf, visit_selected_root_import_half_pages,
};
use crate::analyzer::store::{Result, StoreError};
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionImportSelectorKind, ResolutionRootImportAnchor, ResolutionSiteId, ResolutionSiteKind,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SelectedImportRouteKind {
    SingleType,
    TypeOnDemand,
    SingleStatic,
    StaticOnDemand,
    Named,
    Star,
}

impl SelectedImportRouteKind {
    // The label comes from a persisted catalog or staged row, which this code did
    // not construct, so an unknown label fails the request as a corrupt row
    // instead of panicking the server.
    pub(super) fn from_label(label: &str) -> Result<Self> {
        Ok(match label {
            "single_type" => Self::SingleType,
            "type_on_demand" => Self::TypeOnDemand,
            "single_static" => Self::SingleStatic,
            "static_on_demand" => Self::StaticOnDemand,
            "named" => Self::Named,
            "star" => Self::Star,
            _ => {
                return Err(StoreError::corrupt(format!(
                    "unknown persisted import route kind: {label:?}"
                )));
            }
        })
    }

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::SingleType => "single_type",
            Self::TypeOnDemand => "type_on_demand",
            Self::SingleStatic => "single_static",
            Self::StaticOnDemand => "static_on_demand",
            Self::Named => "named",
            Self::Star => "star",
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct SelectedImportSelector {
    pub(super) kind: ResolutionImportSelectorKind,
    pub(super) source_name: Option<String>,
    pub(super) local_name: Option<String>,
}

#[derive(Clone, Debug)]
pub(super) struct SelectedImportRoute {
    pub(super) kind: SelectedImportRouteKind,
    pub(super) source_site: Option<ResolutionSiteId>,
    pub(super) staged: bool,
}

#[doc(hidden)]
pub struct ImportTokenMetadata {
    pub(super) selector: Option<SelectedImportSelector>,
    pub(super) route: Option<SelectedImportRoute>,
    pub(super) identity_digest: Option<[u8; 32]>,
}

// Scope and both stage epochs cover every mutable SQL input. The source mount
// keeps language-specific rows apart; entries live only for this operation.
#[derive(Debug, PartialEq, Eq, Hash)]
pub(super) struct ImportTokenKey {
    source: SelectedResolutionMountOrdinal,
    blob: i64,
    token: SemanticId,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

pub(super) type ImportTokenMemo = ExactReadMemo<ImportTokenKey, Arc<ImportTokenMetadata>>;

impl SelectedResolutionOperation<'_, '_> {
    #[doc(hidden)]
    pub fn import_token_metadata(
        &self,
        blob: i64,
        source: SelectedResolutionMountOrdinal,
        token: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<Arc<ImportTokenMetadata>>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let key = ImportTokenKey {
            source,
            blob,
            token,
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        };
        if let Some(metadata) = self.import_token_memo.borrow().get(&key) {
            return Ok(Some(Arc::clone(metadata)));
        }
        let (runtime_key, shared_id) =
            super::super::resolution_stage::lexical::semantic_cells(token);
        let metadata = Arc::new(read_import_token_metadata(
            self.ready.inventory.connection(),
            blob,
            token.local_key(),
            source.get(),
            runtime_key,
            shared_id,
        )?);
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        self.import_token_memo
            .borrow_mut()
            .insert(key, Arc::clone(&metadata));
        Ok(Some(metadata))
    }
}

pub(super) struct ImportBinder {
    pub(super) identity: CandidatePathIdentity,
    pub(super) scope: BindingNodeId,
    pub(super) activation: Option<u32>,
    pub(super) anchor: ResolutionRootImportAnchor,
    pub(super) head: String,
    pub(super) bound: Option<String>,
    pub(super) imported: Option<String>,
    pub(super) selector: Option<SelectedImportSelector>,
    pub(super) route: Option<SelectedImportRoute>,
    pub(super) recipes: Vec<ResolutionLookupSemanticRecipe>,
    pub(super) half: SelectedRootPathHalf,
}

pub(super) struct ImportBinderClass {
    pub(super) named: bool,
    /// The route the language admits for later precedence reads. `None` means
    /// the language has no legacy routes.
    pub(super) route: Option<SelectedImportRoute>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ImportBinding<P> {
    pub(super) reference: SemanticId,
    pub(super) token: SemanticId,
    pub(super) precedence: P,
}

/// Supplies import metadata and each language's total precedence order, for
/// example origin rank before depth, or a level-first language's depth first.
/// The shared join never imposes an order of its own.
pub(super) trait ImportBindingRules {
    type Precedence: Copy + Ord;

    fn token_metadata(
        &self,
        blob: i64,
        mount: SelectedResolutionMountOrdinal,
        token: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<std::sync::Arc<ImportTokenMetadata>>>;

    fn binder_rank(&self, language: Language, metadata: &ImportTokenMetadata) -> Option<u32>;

    fn precedence(&self, depth: u32, rank: u32) -> Self::Precedence;
}

pub(super) fn sort_import_bindings<P: Copy + Ord>(bindings: &mut Vec<ImportBinding<P>>) {
    bindings.sort_unstable_by_key(|binding| (binding.reference, binding.precedence, binding.token));
    bindings.dedup_by_key(|binding| (binding.reference, binding.precedence, binding.token));
}

pub(super) fn authored_reference_local_path_evidence(
    ready: &ReadySelectedResolution<'_, '_>,
    reference: SemanticId,
    cancellation: &CancellationToken,
) -> Result<Option<crate::analyzer::resolution::ReferenceLocalPathEvidence>> {
    let lexical = ready.lexical_source();
    let Some(seed) = lexical.reference_seed(ResolutionQuery::new(reference), cancellation)? else {
        return Ok(None);
    };
    if !seed
        .site_metadata()
        .is_some_and(|metadata| metadata.site_kind() != ResolutionSiteKind::SyntheticReference)
    {
        return Ok(None);
    }
    lexical.reference_local_path_evidence(reference, cancellation)
}

/// Pair lookup binders with authored references using producer-side position
/// and lexical-scope evidence. Activation is a producer-side position: a
/// reference that starts before it never binds. Scope membership means the
/// binder scope equals one of the reference's lexical scopes, using the
/// minimum matching depth. A language with a different activation or scope
/// rule extends the rules hook rather than adding a mode flag.
pub(super) fn import_bindings_for_lookup<R: ImportBindingRules>(
    ready: &ReadySelectedResolution<'_, '_>,
    rules: &R,
    mount: SelectedResolutionMountOrdinal,
    lookup: &ResolutionLookupSemanticRecipe,
    cancellation: &CancellationToken,
) -> Result<Option<Vec<ImportBinding<R::Precedence>>>> {
    let record = ready.inventory.mount_record_by_ordinal(mount)?;
    let connection = ready.inventory.connection();
    let lexical = ready.lexical_source();
    let names = ready.shared_names();
    let lookup_semantic = lookup.semantic(&names);
    let mut binders = Vec::new();
    let outcome = visit_selected_root_import_half_pages(
        &ready.context_identities,
        &lexical,
        &lexical,
        Some(&[mount]),
        cancellation,
        &mut FactPageVisitor::new(&mut |page| {
            for half in page {
                let SelectedRootPathHalf::Import {
                    token,
                    demand,
                    source_scope_head,
                    activation,
                    ..
                } = half
                else {
                    continue;
                };
                // The half's demand is the lookup bound in the importing
                // scope, including for wildcard imports. The owner route is
                // separate; another demand through that wildcard is not a
                // competing binder for this name or namespace.
                if *demand != lookup_semantic {
                    continue;
                }
                let Some(metadata) =
                    rules.token_metadata(record.blob_id(), mount, *token, cancellation)?
                else {
                    return Ok(false);
                };
                if let Some(rank) = rules.binder_rank(record.semantic_language(), &metadata) {
                    binders.push((*token, *source_scope_head, *activation, rank));
                }
            }
            Ok(true)
        }),
    )?;
    if outcome.is_cancelled() || cancellation.is_cancelled() {
        return Ok(None);
    }
    binders.sort_unstable();
    binders.dedup();
    // SyntheticReference publishes no site kind or authored metadata.
    // Only published, lowered sites can enter the lexical metadata reader.
    let mut statement = connection.prepare_cached(
        "SELECT DISTINCT semantic.semantic_key
             FROM main.resolution_identities AS lookup
             CROSS JOIN main.resolution_paths AS path
               ON path.blob_id=?1 AND path.end_lead_identity=lookup.id
             JOIN main.resolution_node_catalog AS node
               ON node.blob_id=path.blob_id AND node.local_key=path.start_node
             JOIN main.resolution_semantic_sites AS semantic
               ON semantic.blob_id=node.blob_id AND semantic.semantic_key=node.semantic_local_key
              AND semantic.semantic_role='reference'
             JOIN main.resolution_sites AS authored
               ON authored.blob_id=semantic.blob_id AND authored.site=semantic.source_site
              AND authored.site_kind IS NOT NULL
             WHERE lookup.identity_digest=?2",
    )?;
    let references = statement.query_map(
        rusqlite::params![record.blob_id(), lookup.name_digest().as_slice()],
        |row| row.get::<_, u32>(0),
    )?;
    let mut result = Vec::new();
    for reference in references {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let reference = SemanticId::local(mount.get(), reference?);
        let Some(evidence) =
            authored_reference_local_path_evidence(ready, reference, cancellation)?
        else {
            continue;
        };
        if !evidence.metadata().unqualified()
            || !evidence.local_bindings_certified()
            || !evidence.local_definitions().is_empty()
        {
            continue;
        }
        for &(token, scope, activation, rank) in &binders {
            if activation.is_some_and(|start| evidence.metadata().start_byte() < start as usize) {
                continue;
            }
            if let Some(depth) = evidence
                .lexical_scopes()
                .iter()
                .filter(|(node, _)| *node == scope)
                .map(|(_, depth)| *depth)
                .min()
            {
                result.push(ImportBinding {
                    reference,
                    token,
                    precedence: rules.precedence(depth, rank),
                });
            }
        }
    }
    sort_import_bindings(&mut result);
    Ok(Some(result))
}

pub(super) trait ImportBinderRules {
    fn lookup_recipes(
        &self,
        fragment: BindingFragmentId,
        route: &[SemanticId],
        demand: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<ResolutionLookupSemanticRecipe>>>;

    fn token_metadata(
        &self,
        blob: i64,
        token: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<std::sync::Arc<ImportTokenMetadata>>>;

    fn classify(
        &self,
        selector: Option<&SelectedImportSelector>,
        route: Option<&SelectedImportRoute>,
    ) -> ImportBinderClass;
}

pub(super) fn hydrate_import_binders(
    operation: &ReadySelectedResolution<'_, '_>,
    rules: &impl ImportBinderRules,
    blob: i64,
    fragment: BindingFragmentId,
    halves: Vec<SelectedRootPathHalf>,
    cancellation: &CancellationToken,
) -> Result<Option<Vec<ImportBinder>>> {
    let mut imports = Vec::new();
    for half in halves {
        let SelectedRootPathHalf::Import {
            identity,
            token,
            route,
            demand,
            source_scope_head,
            activation,
            anchor,
            ..
        } = &half
        else {
            continue;
        };
        let Some(recipes) = rules.lookup_recipes(fragment, route, *demand, cancellation)? else {
            return Ok(None);
        };
        let Some(metadata) = rules.token_metadata(blob, *token, cancellation)? else {
            return Ok(None);
        };
        // Preparation already read this authored token's exact catalog or
        // staged coordinate. Share its mounted content identity with the
        // boundary compiler instead of reading its provenance again.
        let digest = metadata
            .identity_digest
            .expect("an authored import token has a catalog or staged identity");
        let fragment_digest = operation.identity_content_digest(fragment.into(), cancellation)?;
        let digest = crate::analyzer::resolution::mounted_identity_digest(
            b"semantic",
            fragment_digest,
            digest,
        );
        operation
            .inventory
            .authority_request_memo()
            .borrow_mut()
            .canonical_digests
            .insert((*token).into(), digest);
        let selector = metadata.selector.clone();
        let class = rules.classify(selector.as_ref(), metadata.route.as_ref());
        let demand_name = recipes.last().expect("an import has a demand").spelling();
        let imported = selector
            .as_ref()
            .and_then(|selector| selector.source_name.as_deref())
            .unwrap_or(demand_name);
        let bound = selector
            .as_ref()
            .and_then(|selector| selector.local_name.as_deref())
            .unwrap_or(imported);
        imports.push(ImportBinder {
            identity: *identity,
            scope: *source_scope_head,
            activation: *activation,
            anchor: *anchor,
            head: recipes
                .first()
                .expect("an import has a head")
                .spelling()
                .to_owned(),
            bound: class.named.then(|| bound.to_owned()),
            imported: class.named.then(|| imported.to_owned()),
            selector,
            route: class.route,
            recipes,
            half,
        });
    }
    Ok(Some(imports))
}

#[cfg(any(test, feature = "test-support"))]
impl ImportTokenMetadata {
    #[doc(hidden)]
    pub fn selected_route_kind(&self) -> Option<&str> {
        self.route.as_ref().map(|route| route.kind.label())
    }
}

// Preserve independent main selector authority and staged route suppression,
// including a staged coordinate whose route is NULL.
#[doc(hidden)]
pub(in crate::analyzer::store) const IMPORT_TOKEN_METADATA: &str = r#"
SELECT selector.kind,selector.source_name,selector.local_name,
       staged.host_ordinal IS NOT NULL,staged.import_route_kind,staged.import_source_site,
       catalog.import_route_kind,catalog.import_source_site,
       CASE WHEN staged.host_ordinal IS NOT NULL THEN staged.identity_digest
            ELSE catalog.identity_digest END
FROM (SELECT 1) AS requested
LEFT JOIN main.resolution_semantic_catalog catalog
 ON catalog.blob_id=?1 AND catalog.local_key=?2
LEFT JOIN main.resolution_import_selectors selector
 ON selector.blob_id=catalog.blob_id AND selector.site=catalog.import_source_site
LEFT JOIN temp.selected_resolution_scope_mounts selected ON selected.mount_ordinal=?3
LEFT JOIN temp.selected_resolution_stage_semantic_coordinates staged
 ON staged.host_ordinal=selected.mount_ordinal
 AND staged.runtime_key IS ?4 AND staged.shared_id IS ?5
"#;

pub(in crate::analyzer::store) const SELECTED_IMPORT_SELECTOR: &str = r#"
SELECT selector.kind, selector.source_name, selector.local_name
FROM main.resolution_semantic_catalog AS catalog
JOIN main.resolution_import_selectors AS selector
  ON selector.blob_id=catalog.blob_id AND selector.site=catalog.import_source_site
WHERE catalog.blob_id=?1 AND catalog.local_key=?2
  AND catalog.import_source_site IS NOT NULL
"#;

struct ImportTokenMetadataRow {
    selector_kind: Option<String>,
    source_name: Option<String>,
    local_name: Option<String>,
    staged: bool,
    staged_kind: Option<String>,
    staged_site: Option<u32>,
    catalog_kind: Option<String>,
    catalog_site: Option<u32>,
    identity_digest: Option<[u8; 32]>,
}

pub(super) fn read_import_token_metadata(
    connection: &rusqlite::Connection,
    blob: i64,
    local_key: Option<u32>,
    source: u32,
    runtime_key: Option<i64>,
    shared_id: Option<i64>,
) -> Result<ImportTokenMetadata> {
    let row = connection
        .prepare_cached(IMPORT_TOKEN_METADATA)?
        .query_row(
            rusqlite::params![blob, local_key, source, runtime_key, shared_id],
            |row| {
                Ok(ImportTokenMetadataRow {
                    selector_kind: row.get(0)?,
                    source_name: row.get(1)?,
                    local_name: row.get(2)?,
                    staged: row.get(3)?,
                    staged_kind: row.get(4)?,
                    staged_site: row.get(5)?,
                    catalog_kind: row.get(6)?,
                    catalog_site: row.get(7)?,
                    identity_digest: row.get(8)?,
                })
            },
        )?;
    decode_import_token_metadata(row)
}

fn decode_import_token_metadata(row: ImportTokenMetadataRow) -> Result<ImportTokenMetadata> {
    let selector = row
        .selector_kind
        .map(|kind| decode_import_selector(kind, row.source_name, row.local_name));
    let (kind, site) = if row.staged {
        (row.staged_kind, row.staged_site)
    } else {
        (row.catalog_kind, row.catalog_site)
    };
    let route = kind
        .map(|kind| {
            let kind = SelectedImportRouteKind::from_label(&kind)?;
            Ok::<_, StoreError>(SelectedImportRoute {
                kind,
                source_site: site.map(ResolutionSiteId::new),
                staged: row.staged,
            })
        })
        .transpose()?;
    Ok(ImportTokenMetadata {
        selector,
        route,
        identity_digest: row.identity_digest,
    })
}

fn decode_import_selector(
    kind: String,
    source_name: Option<String>,
    local_name: Option<String>,
) -> SelectedImportSelector {
    let kind = ResolutionImportSelectorKind::from_label(&kind)
        .expect("selected import-selector kind is constrained by its schema");
    assert!(match kind {
        ResolutionImportSelectorKind::Named => source_name.is_some(),
        ResolutionImportSelectorKind::Star => source_name.is_none() && local_name.is_none(),
        ResolutionImportSelectorKind::ReceiverMember => source_name.is_some(),
    });
    SelectedImportSelector {
        kind,
        source_name,
        local_name,
    }
}

pub(super) fn selected_import_selector(
    connection: &rusqlite::Connection,
    blob_id: i64,
    token: SemanticId,
) -> Result<Option<SelectedImportSelector>> {
    let Some(local_key) = token.local_key() else {
        return Ok(None);
    };
    let row = connection
        .prepare_cached(SELECTED_IMPORT_SELECTOR)?
        .query_row(rusqlite::params![blob_id, local_key], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .optional()?;
    let Some((kind, source_name, local_name)) = row else {
        return Ok(None);
    };
    Ok(Some(decode_import_selector(kind, source_name, local_name)))
}

pub(super) fn selected_import_route(
    inventory: &super::super::resolution_selection::SelectedResolutionMountInventory<'_>,
    blob_id: i64,
    source: SelectedResolutionMountOrdinal,
    token: SemanticId,
) -> Result<Option<SelectedImportRoute>> {
    let connection = inventory.connection();
    let (runtime_key, shared_id) = super::super::resolution_stage::lexical::semantic_cells(token);
    let staged = if inventory
        .stage_family_is_empty(super::super::resolution_stage::StageFamily::SemanticCoordinates)?
    {
        None
    } else {
        connection
        .prepare_cached(
            "SELECT c.import_route_kind,c.import_source_site FROM temp.selected_resolution_stage_semantic_coordinates c
             JOIN temp.selected_resolution_scope_mounts selected ON selected.mount_ordinal=c.host_ordinal
             WHERE c.runtime_key IS ?1 AND c.shared_id IS ?2 AND c.host_ordinal=?3",
        )?
        .query_row(
            rusqlite::params![runtime_key, shared_id, source.get()],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<u32>>(1)?,
                ))
            },
        )
        .optional()?
    };
    if let Some((kind, source_site)) = staged {
        let Some(kind) = kind else {
            return Ok(None);
        };
        return Ok(Some(SelectedImportRoute {
            kind: SelectedImportRouteKind::from_label(&kind)?,
            source_site: source_site.map(ResolutionSiteId::new),
            staged: true,
        }));
    }
    let Some(token_key) = token.local_key() else {
        return Ok(None);
    };
    let route = connection
        .prepare_cached(
            "SELECT import_route_kind,import_source_site FROM main.resolution_semantic_catalog
             WHERE blob_id=?1 AND local_key=?2",
        )?
        .query_row(rusqlite::params![blob_id, token_key], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<u32>>(1)?,
            ))
        })
        .optional()?;
    let Some((kind, source_site)) = route else {
        return Ok(None);
    };
    let Some(kind) = kind else {
        return Ok(None);
    };
    Ok(Some(SelectedImportRoute {
        kind: SelectedImportRouteKind::from_label(&kind)?,
        source_site: source_site.map(ResolutionSiteId::new),
        staged: false,
    }))
}

// The correlated children seek one route's primary key. Reading arrays here
// avoids multiplying each segment by every namespace demand in a join.
macro_rules! route_columns {
    () => {
        "SELECT route.import_site, route.root_scope, route.anchor, route.position,
 route.kind, route.bound_name,
 (SELECT json_group_array(segment ORDER BY position)
  FROM resolution_root_import_segments AS segment
  WHERE segment.blob_id=route.blob_id AND segment.import_site=route.import_site),
 (SELECT json_group_array(json_array(demand.namespace, demand.name,
      demand.target_kind, demand.target_reference, demand.target_name)
      ORDER BY demand.namespace, demand.name)
  FROM resolution_root_import_demands AS demand
  WHERE demand.blob_id=route.blob_id AND demand.import_site=route.import_site)
 FROM resolution_root_imports AS route "
    };
}

#[doc(hidden)]
pub const POINT: &str = concat!(
    route_columns!(),
    "INDEXED BY resolution_root_imports_binding WHERE route.blob_id=?1 AND route.root_scope=?2
 AND (route.bound_name=?3 OR route.kind='glob') ORDER BY route.import_site"
);
#[doc(hidden)]
pub const ENUMERATE: &str = concat!(
    route_columns!(),
    "INDEXED BY resolution_root_imports_binding WHERE route.blob_id=?1 AND route.root_scope=?2 ORDER BY route.import_site"
);
#[doc(hidden)]
pub const AT_SITE: &str = concat!(
    route_columns!(),
    "WHERE route.blob_id=?1 AND route.import_site=?2"
);
/// A token is a semantic catalog key, never a source import ordinal.
#[doc(hidden)]
pub const TOKEN_SITE: &str = "SELECT import_source_site FROM resolution_semantic_catalog
 WHERE blob_id=?1 AND local_key=?2 AND import_source_site IS NOT NULL";

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[doc(hidden)]
pub struct ImportDemand(
    pub i64,
    pub String,
    pub Option<String>,
    pub Option<u32>,
    pub Option<String>,
);

#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct ImportRoute {
    pub site: u32,
    pub scope: u32,
    pub anchor: String,
    pub position: Option<usize>,
    pub kind: String,
    pub bound_name: Option<String>,
    pub segments: Vec<String>,
    pub demands: Vec<ImportDemand>,
}

impl ImportRoute {
    #[doc(hidden)]
    pub fn named_path(&self, namespace: i64) -> Option<Vec<String>> {
        if self.kind != "named" {
            return None;
        }
        let demand = self.demands.iter().find(|d| d.0 == namespace)?;
        let mut path = self.segments.clone();
        path.push(demand.4.clone()?);
        Some(path)
    }
}

fn read_route(row: &rusqlite::Row<'_>) -> rusqlite::Result<ImportRoute> {
    let decode = |column| -> rusqlite::Result<serde_json::Value> {
        let text: String = row.get(column)?;
        serde_json::from_str(&text).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                column,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })
    };
    let segments = serde_json::from_value(decode(6)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let demands = serde_json::from_value(decode(7)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(ImportRoute {
        site: row.get(0)?,
        scope: row.get(1)?,
        anchor: row.get(2)?,
        position: row.get(3)?,
        kind: row.get(4)?,
        bound_name: row.get(5)?,
        segments,
        demands,
    })
}

#[doc(hidden)]
pub fn named_routes(
    connection: &Connection,
    blob: i64,
    scope: u32,
    name: &str,
    cancellation: &CancellationToken,
) -> Result<Option<Vec<ImportRoute>>> {
    let mut routes = Vec::new();
    for row in connection
        .prepare_cached(POINT)?
        .query_map(params![blob, scope, name], read_route)?
    {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        routes.push(row?);
    }
    Ok(Some(routes))
}

#[doc(hidden)]
pub fn scope_routes(
    connection: &Connection,
    blob: i64,
    scope: u32,
    cancellation: &CancellationToken,
) -> Result<Option<Vec<ImportRoute>>> {
    let mut routes = Vec::new();
    for row in connection
        .prepare_cached(ENUMERATE)?
        .query_map(params![blob, scope], read_route)?
    {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        routes.push(row?);
    }
    Ok(Some(routes))
}

#[doc(hidden)]
pub fn route_at_site(connection: &Connection, blob: i64, site: u32) -> Result<Option<ImportRoute>> {
    use rusqlite::OptionalExtension;
    Ok(connection
        .prepare_cached(AT_SITE)?
        .query_row(params![blob, site], read_route)
        .optional()?)
}

impl super::SelectedResolutionOperation<'_, '_> {
    pub(super) fn import_lookup_recipes(
        &self,
        fragment: BindingFragmentId,
        semantics: &[SemanticId],
        cancellation: &CancellationToken,
        observe_read: impl Fn(&super::SelectedLookupRecipeRequest),
    ) -> Result<Option<Vec<ResolutionLookupSemanticRecipe>>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let requests = semantics
            .iter()
            .map(|&semantic| super::SelectedLookupRecipeRequest { fragment, semantic })
            .collect::<Vec<_>>();
        let Some(rows) = self.read_context_recipes(
            &self.ready.lexical_source(),
            &requests,
            cancellation,
            observe_read,
        )?
        else {
            return Ok(None);
        };
        let recipes = rows
            .into_iter()
            .zip(&requests)
            .map(|(row, request)| {
                if let Some(recipe) = row {
                    return Ok(recipe);
                }
                let mount = self
                    .mount_table()
                    .mount_for_fragment(request.fragment)?
                    .expect("selected import fragment is mounted");
                Err(StoreError::corrupt(format!(
                    "selected import semantic lacks its lookup recipe: language={:?}",
                    mount.semantic_language()
                )))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((!cancellation.is_cancelled()).then_some(recipes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_coordinate_decode_preserves_stage_authority_and_rejects_unknown_routes() {
        let staged_null = decode_import_token_metadata(ImportTokenMetadataRow {
            selector_kind: Some("named".to_owned()),
            source_name: Some("source".to_owned()),
            local_name: Some("local".to_owned()),
            staged: true,
            staged_kind: None,
            staged_site: None,
            catalog_kind: Some("single_type".to_owned()),
            catalog_site: Some(11),
            identity_digest: None,
        })
        .unwrap();
        let selector = staged_null
            .selector
            .as_ref()
            .expect("catalog selector remains");
        assert_eq!(selector.kind, ResolutionImportSelectorKind::Named);
        assert_eq!(selector.source_name.as_deref(), Some("source"));
        assert_eq!(selector.local_name.as_deref(), Some("local"));
        assert!(staged_null.route.is_none());
        assert!(staged_null.identity_digest.is_none());

        let catalog = decode_import_token_metadata(ImportTokenMetadataRow {
            selector_kind: None,
            source_name: None,
            local_name: None,
            staged: false,
            staged_kind: None,
            staged_site: None,
            catalog_kind: Some("single_type".to_owned()),
            catalog_site: Some(11),
            identity_digest: Some([7; 32]),
        })
        .unwrap();
        let route = catalog.route.expect("catalog route remains");
        assert_eq!(route.kind, SelectedImportRouteKind::SingleType);
        assert_eq!(route.source_site, Some(ResolutionSiteId::new(11)));
        assert!(!route.staged);
        assert_eq!(catalog.identity_digest, Some([7; 32]));

        assert!(matches!(
            decode_import_token_metadata(ImportTokenMetadataRow {
                selector_kind: None,
                source_name: None,
                local_name: None,
                staged: false,
                staged_kind: None,
                staged_site: None,
                catalog_kind: Some("unknown".to_owned()),
                catalog_site: Some(11),
                identity_digest: None,
            }),
            Err(error) if error.kind == crate::analyzer::store::StoreErrorKind::Corrupt
        ));
    }

    #[test]
    fn selected_import_selector_reader_uses_exact_persisted_fact_rows() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE resolution_semantic_catalog (
                    blob_id INTEGER NOT NULL,
                    local_key INTEGER NOT NULL,
                    import_source_site INTEGER,
                    PRIMARY KEY(blob_id, local_key)
                 ) WITHOUT ROWID;
                 CREATE TABLE resolution_import_selectors (
                    blob_id INTEGER NOT NULL,
                    site INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    source_name TEXT,
                    local_name TEXT,
                    PRIMARY KEY(blob_id, site)
                 ) WITHOUT ROWID;
                 INSERT INTO resolution_semantic_catalog VALUES (7, 10, 50), (7, 11, 51), (7, 12, NULL);
                 INSERT INTO resolution_import_selectors VALUES
                    (7, 50, 'named', 'Original', 'Renamed'),
                    (7, 51, 'star', NULL, NULL);",
            )
            .unwrap();

        let named = selected_import_selector(&connection, 7, SemanticId::local(0, 10))
            .unwrap()
            .unwrap();
        assert_eq!(named.kind, ResolutionImportSelectorKind::Named);
        assert_eq!(named.source_name.as_deref(), Some("Original"));
        assert_eq!(named.local_name.as_deref(), Some("Renamed"));

        let star = selected_import_selector(&connection, 7, SemanticId::local(0, 11))
            .unwrap()
            .unwrap();
        assert_eq!(star.kind, ResolutionImportSelectorKind::Star);
        assert!(star.source_name.is_none() && star.local_name.is_none());
        assert!(
            selected_import_selector(&connection, 7, SemanticId::local(0, 12))
                .unwrap()
                .is_none()
        );

        let mut plan = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {SELECTED_IMPORT_SELECTOR}"))
            .unwrap();
        let plan = plan
            .query_map(rusqlite::params![7, 10], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(plan.iter().all(|step| step.contains("SEARCH")), "{plan:?}");
    }
}
