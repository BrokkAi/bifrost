//! Request-local indexed reverse nominations, independent of language policy.

use super::*;
use std::borrow::Cow;

// These are coordinates in the enclosing selected operation, whose final
// authority check validates revision/configuration and overlays. They do not
// claim that a selected-unit summary exists.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct ReverseContextWitness {
    pub(crate) mount: u32,
    pub(crate) blob: i64,
    pub(super) selection: [u8; 32],
    pub(super) analysis_generation: u64,
}

impl ReverseContextWitness {
    #[doc(hidden)]
    pub fn new(operation: &SelectedResolutionOperation<'_, '_>, mount: u32, blob: i64) -> Self {
        Self {
            mount,
            blob,
            selection: operation.ready.inventory.fingerprint(),
            analysis_generation: operation.ready.analysis_generation,
        }
    }

    pub(crate) fn assert_selected(&self, operation: &SelectedResolutionOperation<'_, '_>) {
        assert_eq!(
            self.selection,
            operation.ready.inventory.fingerprint(),
            "a reverse witness belongs to its selected inventory"
        );
        assert_eq!(
            self.analysis_generation, operation.ready.analysis_generation,
            "a reverse witness belongs to its captured overlay generation"
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub enum ReverseNominationRoute {
    Lookup,
    Root,
    Qualified,
    #[cfg(any(test, feature = "test-support"))]
    Range,
}

/// A request-sized set of selected lookup keys. Language hook arms may
/// append nominations beside the shared reader without changing these arms.
#[doc(hidden)]
pub struct ReverseCandidateKey {
    #[doc(hidden)]
    pub input_ordinal: usize,
    #[doc(hidden)]
    pub context: ReverseContextWitness,
    #[doc(hidden)]
    pub lookup: SemanticId,
    #[doc(hidden)]
    pub root: bool,
    #[doc(hidden)]
    pub lexical: bool,
    #[doc(hidden)]
    pub qualified: bool,
}

#[derive(Debug)]
#[doc(hidden)]
pub struct ReverseIndexedCandidate {
    #[doc(hidden)]
    pub input_ordinal: usize,
    #[doc(hidden)]
    pub context: ReverseContextWitness,
    pub(crate) persisted_lookup: i64,
    #[doc(hidden)]
    pub site: ResolutionSiteId,
    #[doc(hidden)]
    pub route: ReverseNominationRoute,
    /// Path id, qualified reference/precedence, or (i64::MAX, inventory reference).
    #[doc(hidden)]
    pub provenance: (i64, i64),
}

pub(crate) const REVERSE_CANDIDATE_KEYS_DDL: &str =
    "CREATE TEMP TABLE IF NOT EXISTS reverse_candidate_keys(
    key_ordinal INTEGER PRIMARY KEY, input_ordinal INTEGER NOT NULL,
    blob INTEGER NOT NULL, lookup INTEGER NOT NULL,
    root INTEGER NOT NULL, qualified INTEGER NOT NULL, lexical INTEGER NOT NULL) STRICT";
pub(crate) const REVERSE_CANDIDATE_KEYS_CLEAR_SQL: &str = "DELETE FROM temp.reverse_candidate_keys";
pub(crate) const REVERSE_CANDIDATE_KEYS_INSERT_SQL: &str = "INSERT INTO temp.reverse_candidate_keys
     SELECT value->>0,value->>1,value->>2,value->>3,value->>4,value->>5,value->>6
     FROM json_each(?1)";

pub(crate) const REVERSE_CANDIDATES_SQL: &str = r#"
SELECT k.key_ordinal,k.input_ordinal,k.blob,k.lookup,s.site,0 AS route,p.path AS provenance,0 AS secondary
FROM temp.reverse_candidate_keys k
CROSS JOIN main.resolution_paths p INDEXED BY resolution_paths_end_lookup_identity
  ON p.blob_id=k.blob AND p.end_lead_identity=k.lookup
JOIN main.resolution_sites s ON s.blob_id=p.blob_id AND s.site=p.start_node AND s.role=0
WHERE k.lexical
UNION ALL
SELECT k.key_ordinal,k.input_ordinal,k.blob,k.lookup,s.site,1,p.path,0
FROM temp.reverse_candidate_keys k
CROSS JOIN main.resolution_paths p INDEXED BY resolution_paths_root_terminal
  ON p.blob_id=k.blob AND p.root_terminal=k.lookup AND p.end_node=-1
JOIN main.resolution_sites s ON s.blob_id=p.blob_id AND s.site=p.start_node AND s.role=0
WHERE k.root AND json_array_length(p.body,'$[4]')>3
  AND NOT EXISTS(SELECT 1 FROM main.resolution_identities i
    WHERE i.id=-coalesce(json_extract(p.body,'$[4][1][0]'),json_extract(p.body,'$[4][1]'))
      AND i.namespace IS NOT NULL)
UNION ALL
SELECT k.key_ordinal,k.input_ordinal,k.blob,k.lookup,s.site,2,q.reference,q.precedence_ordinal
FROM temp.reverse_candidate_keys k
CROSS JOIN main.resolution_qualified_routes q INDEXED BY resolution_qualified_routes_source_lookup
  ON q.blob_id=k.blob AND q.source_lookup=k.lookup
JOIN main.resolution_sites s ON s.blob_id=q.blob_id AND s.site=q.reference AND s.role=0
WHERE k.qualified
ORDER BY 1,6,7,8
"#;

/// Source spelling inventory can nominate references that have no lexical path.
/// Opting into this arm is a language rule; the selected reader still owns
/// authority validation, input grouping, provenance order and coalescing.
/// Local path keys fit u32. The i64::MAX inventory marker sorts after those
/// paths, retaining their provenance when a (site, route) pair overlaps.
#[doc(hidden)]
pub const REVERSE_LOOKUP_IDENTITY_ARM_SQL: &str = r#"
SELECT k.key_ordinal,k.input_ordinal,k.blob,k.lookup,s.site,0 AS route,9223372036854775807 AS provenance,n.semantic_key AS secondary
FROM temp.reverse_candidate_keys k
CROSS JOIN main.resolution_reference_lookup_identities n
  INDEXED BY resolution_reference_lookup_identities_identity
  ON n.identity_id=k.lookup AND n.blob_id=k.blob
JOIN main.resolution_semantic_sites reference
  ON reference.blob_id=n.blob_id AND reference.semantic_role='reference'
  AND reference.semantic_key=n.semantic_key
JOIN main.resolution_sites s
  ON s.blob_id=reference.blob_id AND s.site=reference.source_site AND s.role=0
WHERE k.lexical
"#;

/// Assemble a static per-language arm list. No names or request data enter SQL.
/// The original entry uses the original literal, with no new SQL statements.
pub(crate) fn reverse_candidates_sql(arms: &'static [&'static str]) -> Cow<'static, str> {
    const ORDER: &str = "ORDER BY 1,6,7,8\n";
    if arms.is_empty() {
        return Cow::Borrowed(REVERSE_CANDIDATES_SQL);
    }
    let mut sql = REVERSE_CANDIDATES_SQL
        .strip_suffix(ORDER)
        .expect("the shared candidate UNION has one terminal ordering")
        .to_owned();
    for arm in arms {
        sql.push_str("UNION ALL\n");
        sql.push_str(arm);
        sql.push('\n');
    }
    sql.push_str(ORDER);
    Cow::Owned(sql)
}

/// Supplemental arms return the same eight columns and route tags (0, 1, 2)
/// as the shared UNION. A language selects a static list, never a request mode.
#[doc(hidden)]
pub fn read_reverse_candidates_with_arms(
    operation: &SelectedResolutionOperation<'_, '_>,
    keys: &[ReverseCandidateKey],
    arms: &'static [&'static str],
    cancellation: &CancellationToken,
) -> Result<Option<Vec<Vec<ReverseIndexedCandidate>>>> {
    read_reverse_candidates_sql(operation, keys, &reverse_candidates_sql(arms), cancellation)
}

/// Groups preserve empty inputs, selected/overlay authority and path provenance.
/// Each key coalesces identical (site, route) pairs, keeping the first path
/// provenance in arm/path order. The request-sized TEMP relation contains only
/// this call's keys. It is cleared on failed validation, read errors and cancellation.
#[doc(hidden)]
pub fn read_reverse_candidates(
    operation: &SelectedResolutionOperation<'_, '_>,
    keys: &[ReverseCandidateKey],
    cancellation: &CancellationToken,
) -> Result<Option<Vec<Vec<ReverseIndexedCandidate>>>> {
    read_reverse_candidates_sql(operation, keys, REVERSE_CANDIDATES_SQL, cancellation)
}

fn read_reverse_candidates_sql(
    operation: &SelectedResolutionOperation<'_, '_>,
    keys: &[ReverseCandidateKey],
    sql: &str,
    cancellation: &CancellationToken,
) -> Result<Option<Vec<Vec<ReverseIndexedCandidate>>>> {
    use crate::analyzer::resolution::SharedNameInterner;
    let connection = operation.ready.inventory.connection();
    operation
        .ready
        .inventory
        .ensure_reverse_candidate_keys_schema()?;
    let cleared = connection.execute(REVERSE_CANDIDATE_KEYS_CLEAR_SQL, [])?;
    operation
        .ready
        .inventory
        .account_committed_request_changes(cleared as u64);
    let result = (|| {
        let lexical = operation.ready.lexical_source();
        let mut requested = Vec::with_capacity(keys.len());
        let mut validated = HashSet::default();
        for (position, key) in keys.iter().enumerate() {
            key.context.assert_selected(operation);
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            // All namespace keys for a blob read the same selected authority.
            // Keep this memo within this one request-key read.
            if validated.insert(key.context.blob)
                && lexical
                    .validate_reverse_candidate_blob(key.context.blob, cancellation)?
                    .is_none()
            {
                return Ok(None);
            }
            let Some(identity) = key
                .lookup
                .shared_name_id()
                .and_then(|name| operation.ready.shared_names().to_persisted(name))
            else {
                continue;
            };
            requested.push((
                position,
                key.input_ordinal,
                key.context.blob,
                identity.get(),
                key.root,
                key.qualified,
                key.lexical,
            ));
        }
        let requested = serde_json::to_string(&requested)
            .expect("reverse candidate request keys serialize as JSON");
        super::super::resolution::with_resolution_read_progress_handler(
            connection,
            cancellation,
            |connection| {
                let inserted = connection
                    .prepare_cached(REVERSE_CANDIDATE_KEYS_INSERT_SQL)?
                    .execute([requested])?;
                operation
                    .ready
                    .inventory
                    .account_committed_request_changes(inserted as u64);
                let mut groups: Vec<Vec<ReverseIndexedCandidate>> =
                    keys.iter().map(|_| Vec::new()).collect();
                let mut statement = connection.prepare_cached(sql)?;
                let mut rows = statement.query([])?;
                while let Some(row) = rows.next()? {
                    let position: usize = row.get(0)?;
                    let context = keys[position].context.clone();
                    debug_assert_eq!(context.blob, row.get::<_, i64>(2)?);
                    groups[position].push(ReverseIndexedCandidate {
                        input_ordinal: row.get(1)?,
                        context,
                        persisted_lookup: row.get(3)?,
                        site: ResolutionSiteId::new(row.get(4)?),
                        route: match row.get::<_, u8>(5)? {
                            0 => ReverseNominationRoute::Lookup,
                            1 => ReverseNominationRoute::Root,
                            2 => ReverseNominationRoute::Qualified,
                            _ => unreachable!("shared candidate arm"),
                        },
                        provenance: (row.get(6)?, row.get(7)?),
                    });
                }
                for group in &mut groups {
                    let mut seen = HashSet::default();
                    group.retain(|candidate| seen.insert((candidate.site, candidate.route)));
                }
                Ok(Some(groups))
            },
        )
    })();
    let cleared = connection.execute(REVERSE_CANDIDATE_KEYS_CLEAR_SQL, [])?;
    operation
        .ready
        .inventory
        .account_committed_request_changes(cleared as u64);
    match result {
        Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => Ok(None),
        Ok(_) if cancellation.is_cancelled() => Ok(None),
        result => result,
    }
}
