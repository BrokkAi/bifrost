//! Indexed, blob-local import syntax. Results live only for the current request.
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;

use super::SelectedResolutionMountOrdinal;
use crate::CancellationToken;
use crate::analyzer::resolution::SemanticId;
use crate::analyzer::store::{Result, StoreError};
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionImportSelectorKind, ResolutionSiteId,
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
