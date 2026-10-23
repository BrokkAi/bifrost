//! Indexed, blob-local import syntax. Results live only for the current request.
use rusqlite::{Connection, params};
use serde::Deserialize;

use crate::CancellationToken;
use crate::analyzer::store::Result;

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
mod tests {}
