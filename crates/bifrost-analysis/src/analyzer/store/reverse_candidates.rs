//! Request-local indexed reverse nominations, independent of language policy.

use super::*;

// These are coordinates in the enclosing selected operation, whose final
// authority check validates revision/configuration and overlays. They do not
// claim that a selected-unit summary exists.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ReverseContextWitness {
    pub(crate) mount: u32,
    pub(crate) blob: i64,
    pub(super) selection: [u8; 32],
    pub(super) analysis_generation: u64,
}

impl ReverseContextWitness {
    pub(crate) fn new(
        operation: &SelectedResolutionOperation<'_, '_>,
        mount: u32,
        blob: i64,
    ) -> Self {
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
pub(crate) enum ReverseNominationRoute {
    Lookup,
    Root,
    Qualified,
    #[cfg(any(test, feature = "test-support"))]
    Range,
}

/// A request-sized set of selected lookup keys. Language hook arms may
/// append nominations beside the shared reader without changing these arms.
pub(crate) struct ReverseCandidateKey {
    pub(crate) input_ordinal: usize,
    pub(crate) context: ReverseContextWitness,
    pub(crate) lookup: SemanticId,
    pub(crate) root: bool,
    pub(crate) lexical: bool,
    pub(crate) qualified: bool,
}

pub(crate) struct ReverseIndexedCandidate {
    pub(crate) input_ordinal: usize,
    pub(crate) context: ReverseContextWitness,
    pub(crate) persisted_lookup: i64,
    pub(crate) site: ResolutionSiteId,
    pub(crate) route: ReverseNominationRoute,
    /// Path id, or qualified reference and precedence ordinal.
    pub(crate) provenance: (i64, i64),
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

/// Groups preserve empty inputs, selected/overlay authority and path provenance.
/// Each key coalesces identical (site, route) pairs, keeping the first path
/// provenance in arm/path order. The request-sized TEMP relation contains only
/// this call's keys. It is cleared on failed validation, read errors and cancellation.
pub(crate) fn read_reverse_candidates(
    operation: &SelectedResolutionOperation<'_, '_>,
    keys: &[ReverseCandidateKey],
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
                let mut statement = connection.prepare_cached(REVERSE_CANDIDATES_SQL)?;
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
