//! Writer-owned source replacement capabilities and publication planning.
//! Ordinary callers can publish products; only explicit repair or a transaction
//! proving missing/unavailable canonical source can reach the replacement writer.

use super::derived_publication::{DerivedProducts, DerivedReplacement};
use super::*;

/// The publication an exact decoder observed, without claiming its rows intact.
/// A delayed integrity failure may withdraw this nonce only.
pub(super) struct SourceReadPublication {
    key: BlobKey,
    generation: GenerationId,
    blob_id: i64,
    witness: Option<i64>,
}

impl SourceReadPublication {
    pub(super) fn capture(
        conn: &Connection,
        key: &BlobKey,
        generation: GenerationId,
    ) -> Result<Option<Self>> {
        Ok(conn
            .prepare_cached(
                "SELECT blob.id, meta.publication_witness FROM blobs AS blob
             JOIN blob_meta AS meta ON meta.blob_id = blob.id
             WHERE blob.blob_oid = ?1 AND blob.lang = ?2 AND blob.parse_variant = ?3
               AND blob.generation = ?4 AND meta.is_complete = 1",
            )?
            .query_row(
                params![key.oid.to_string(), key.lang, key.variant, generation.get()],
                |row| {
                    Ok(Self {
                        key: key.clone(),
                        generation,
                        blob_id: row.get(0)?,
                        witness: row.get(1)?,
                    })
                },
            )
            .optional()?)
    }

    pub(super) fn withdraw(self, store: &AnalyzerStore) -> Result<()> {
        let key = self.key;
        store.conn.execute(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(
                "UPDATE blob_meta SET is_complete = 0
                 WHERE blob_id = ?1 AND publication_witness IS ?2
                   AND EXISTS (SELECT 1 FROM blobs WHERE id = ?1
                     AND blob_oid = ?3 AND lang = ?4 AND parse_variant = ?5 AND generation = ?6)",
                params![
                    self.blob_id,
                    self.witness,
                    key.oid.to_string(),
                    key.lang,
                    key.variant,
                    self.generation.get()
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }
}

#[derive(Clone, Copy)]
pub(super) struct StoredBlobReplacementCost {
    pub(super) cascade: StoredCascadeCost,
    pub(super) restored_roots: PersistedMutationCost,
    pub(super) generation: Option<GenerationId>,
}

/// Private construction distinguishes an explicit repair from ordinary work.
struct ExplicitRepair {
    prepared: PreparedParsedBlob,
}

#[derive(Clone, Copy)]
pub(super) struct ExplicitRepairRef<'a> {
    prepared: &'a PreparedParsedBlob,
}

impl<'a> ExplicitRepairRef<'a> {
    pub(super) fn prepared(self) -> &'a PreparedParsedBlob {
        self.prepared
    }
}

impl PreparedPersistenceEnvelope for ExplicitRepair {
    fn fragment_count(&self) -> usize {
        self.prepared.fragment_count()
    }
    fn fragment_at(&self, ordinal: usize) -> PreparedPublicationRef<'_> {
        PreparedPublicationRef::Repair(ExplicitRepairRef {
            prepared: self.prepared.fragment_at(ordinal),
        })
    }
    fn publication_fragments(&self) -> Vec<PreparedPublicationRef<'_>> {
        let mut fragments = Vec::with_capacity(self.prepared.fragment_count());
        self.prepared.append_fragments(&mut fragments);
        fragments
            .into_iter()
            .map(|prepared| PreparedPublicationRef::Repair(ExplicitRepairRef { prepared }))
            .collect()
    }
}

/// The connection-taking explicit repair entry used by both writer backends.
/// Its private envelope is the only way to request replacement of healthy source.
pub(super) fn repair_prepared_blobs_on_connection(
    conn: &mut Connection,
    prepared: Vec<PreparedParsedBlob>,
    counters: PreparedWriteCounters,
    cancellation: CancellationToken,
    limits: PersistBatchTargets,
) -> (Vec<PersistBlobOutcome>, PersistBatchStats) {
    let repairs = prepared
        .into_iter()
        .map(|prepared| ExplicitRepair { prepared })
        .collect();
    let (outcomes, stats) = PreparedPersistenceWriter::new(conn, counters, cancellation)
        .persist_prepared_blobs(repairs, limits);
    (
        outcomes
            .into_iter()
            .map(|outcome| PersistBlobOutcome {
                prepared: outcome.prepared.prepared,
                error: outcome.error,
            })
            .collect(),
        stats,
    )
}

/// Bound to the writer transaction that proved source replacement admissible.
/// Neither its fields nor its constructor are available to other store modules.
struct SourceReplacement<'a, 'conn> {
    tx: &'a Transaction<'conn>,
    prepared: &'a PreparedParsedBlob,
}

enum PublicationWrite<'a, 'conn> {
    Source(SourceReplacement<'a, 'conn>),
    PinnedDerived {
        products: DerivedProducts<'a>,
        replacement: DerivedReplacement,
    },
    AdoptedDerived {
        prepared: &'a PreparedParsedBlob,
        source: SourcePublicationWitness,
        replacement: DerivedReplacement,
    },
}

pub(super) struct PublicationPlan<'a, 'conn> {
    tx: &'a Transaction<'conn>,
    write: PublicationWrite<'a, 'conn>,
    cost: PersistedMutationCost,
}

impl PublicationPlan<'_, '_> {
    pub(super) fn cost(&self) -> PersistedMutationCost {
        self.cost
    }

    pub(super) fn publish(
        self,
        cancellation: &CancellationToken,
    ) -> Result<(i64, PersistedMutationCost)> {
        if cancellation.is_cancelled() {
            return Err(StoreError::cancelled("source publication was cancelled"));
        }
        match self.write {
            PublicationWrite::Source(source) => source.publish(cancellation),
            PublicationWrite::PinnedDerived {
                products,
                replacement,
            } => {
                let id = products.source().blob_id();
                Ok((id, products.publish(self.tx, replacement, cancellation)?))
            }
            PublicationWrite::AdoptedDerived {
                prepared,
                source,
                replacement,
            } => {
                let products = DerivedProducts::from_parsed(&source, prepared);
                Ok((
                    source.blob_id(),
                    products.publish(self.tx, replacement, cancellation)?,
                ))
            }
        }
    }
}

fn require_prepared_publication_authorities(
    tx: &Transaction<'_>,
    fragments: &[PreparedPublicationRef<'_>],
    counters: &PreparedWriteCounters,
) -> Result<()> {
    #[cfg(not(any(test, feature = "test-support")))]
    let _ = counters;
    let mut generations = HashMap::default();
    let mut producer_epochs = HashMap::default();
    let mut semantic_epochs = HashMap::default();
    for blob in fragments {
        if let Some(existing) = generations.insert(blob.lang(), blob.generation())
            && existing != blob.generation()
        {
            return Err(StoreError::stale_generation(format!(
                "conflicting prepared generations for language {}",
                blob.lang()
            )));
        }
        let expected = blob.resolution().producer_epoch();
        if let Some(existing) = producer_epochs.insert(blob.lang(), expected)
            && existing != expected
        {
            return Err(StoreError::stale_resolution(format!(
                "conflicting prepared resolution epochs for language {}",
                blob.lang()
            )));
        }
    }
    for blob in fragments {
        if let Some(prepared) = blob.semantic_ir() {
            let epoch = prepared.producer_epoch();
            if let Some(existing) = semantic_epochs.insert(blob.lang(), epoch)
                && existing != epoch
            {
                return Err(StoreError::stale_resolution(format!(
                    "conflicting prepared IR producers for {}",
                    blob.lang()
                )));
            }
        }
    }
    for (lang, generation) in generations {
        #[cfg(any(test, feature = "test-support"))]
        counters.generation_lookups.fetch_add(1, Ordering::SeqCst);
        require_current_generation(tx, lang, generation)?;
    }
    for (lang, epoch) in producer_epochs {
        resolution::require_active_resolution_epoch(tx, lang, epoch)?;
    }
    for (lang, expected) in semantic_epochs {
        let active: Option<String> = tx
            .prepare_cached("SELECT producer_epoch FROM semantic_ir_producer_epochs WHERE lang=?1")?
            .query_row([lang], |row| row.get(0))
            .optional()?;
        if active.as_deref() != Some(expected) {
            return Err(StoreError::stale_resolution(format!(
                "semantic IR producer moved before publication: {lang}"
            )));
        }
    }
    Ok(())
}

/// The batched lookup is the source of replacement authority. New blobs need
/// no additional source-readiness query; existing ordinary sources are adopted
/// when they have become healthy, including a missing-to-healthy scheduling race.
pub(super) fn prepare_publication_plans<'a, 'conn>(
    tx: &'a Transaction<'conn>,
    fragments: &[PreparedPublicationRef<'a>],
    counters: &PreparedWriteCounters,
) -> Result<Vec<PublicationPlan<'a, 'conn>>> {
    require_prepared_publication_authorities(tx, fragments, counters)?;
    let sources = fragments
        .iter()
        .filter_map(|fragment| match fragment {
            PreparedPublicationRef::Source(blob) => Some(*blob),
            PreparedPublicationRef::Repair(repair) => Some(repair.prepared()),
            PreparedPublicationRef::Derived(_) => None,
        })
        .collect::<Vec<_>>();
    let mut costs = stored_blob_cascade_costs_conn(tx, &sources, || {
        #[cfg(any(test, feature = "test-support"))]
        counters.replacement_lookups.fetch_add(1, Ordering::SeqCst);
    })?
    .into_iter();
    let mut plans = Vec::with_capacity(fragments.len());
    for &fragment in fragments {
        let (write, cost) = match fragment {
            PreparedPublicationRef::Derived(blob) => {
                let products = blob.products();
                let replacement = products.replacement(tx)?;
                let cost = replacement.cost(&products);
                (
                    PublicationWrite::PinnedDerived {
                        products,
                        replacement,
                    },
                    cost,
                )
            }
            PreparedPublicationRef::Source(blob) => {
                let mut stored = costs.next().expect("one source cost per source fragment");
                let healthy = match stored.cascade {
                    StoredCascadeCost::Missing => None,
                    StoredCascadeCost::Known(_) | StoredCascadeCost::Legacy => {
                        match SourcePublicationWitness::read(tx, &blob.key) {
                            Ok(source) => source,
                            Err(error) if error.is_corrupt() => None,
                            Err(error) => return Err(error),
                        }
                    }
                };
                if let Some(source) = healthy {
                    let products = DerivedProducts::from_parsed(&source, blob);
                    let replacement = products.replacement(tx)?;
                    let cost = replacement.cost(&products);
                    (
                        PublicationWrite::AdoptedDerived {
                            prepared: blob,
                            source,
                            replacement,
                        },
                        cost,
                    )
                } else {
                    // A damaged publication's cached cost is no longer proof.
                    if stored.generation == Some(blob.generation) {
                        stored.cascade = StoredCascadeCost::Legacy;
                    }
                    let cost = replacement_cost(tx, blob, stored, counters)?;
                    (
                        PublicationWrite::Source(SourceReplacement { tx, prepared: blob }),
                        cost,
                    )
                }
            }
            PreparedPublicationRef::Repair(repair) => {
                let blob = repair.prepared();
                let stored = costs
                    .next()
                    .expect("one source cost per explicit repair fragment");
                let cost = replacement_cost(tx, blob, stored, counters)?;
                (
                    PublicationWrite::Source(SourceReplacement { tx, prepared: blob }),
                    cost,
                )
            }
        };
        plans.push(PublicationPlan { tx, write, cost });
    }
    assert!(costs.next().is_none());
    Ok(plans)
}

fn replacement_cost(
    tx: &Transaction<'_>,
    blob: &PreparedParsedBlob,
    stored: StoredBlobReplacementCost,
    counters: &PreparedWriteCounters,
) -> Result<PersistedMutationCost> {
    #[cfg(not(any(test, feature = "test-support")))]
    let _ = counters;
    let replaced = match stored.cascade {
        StoredCascadeCost::Missing => PersistedMutationCost::default(),
        StoredCascadeCost::Known(cost) => cost,
        StoredCascadeCost::Legacy => {
            #[cfg(any(test, feature = "test-support"))]
            counters
                .replacement_fallbacks
                .fetch_add(1, Ordering::SeqCst);
            let mut statement = tx.prepare_cached(persisted_blob_mutation_cost_fallback_sql())?;
            persisted_blob_mutation_cost_fallback_statement(&mut statement, &blob.key)?
        }
    };
    Ok(PersistedMutationCost {
        logical_rows: blob
            .logical_rows()
            .saturating_add(replaced.logical_rows)
            .saturating_add(stored.restored_roots.logical_rows),
        payload_bytes: blob
            .payload_bytes()
            .saturating_add(replaced.payload_bytes)
            .saturating_add(stored.restored_roots.payload_bytes),
    })
}

impl SourceReplacement<'_, '_> {
    fn publish(self, cancellation: &CancellationToken) -> Result<(i64, PersistedMutationCost)> {
        let tx = self.tx;
        let blob = self.prepared;
        let blob_id = write_prepared_blob_rows_tx(self, cancellation)?;
        if let Some(support) = store_language_support(blob.resolution.semantic_language()) {
            support.publish_native_resolution_rows(
                tx,
                blob_id,
                &blob.state.resolution_facts,
                cancellation,
            )?;
        }
        let (_, surface_cost) = surface_relations::ensure_surface_set_tx(tx, blob_id)?;
        csharp_compilation::extent::content_available(tx, &blob.key.lang, blob_id)?;
        brokk_bifrost_core::definition_inventory::reconcile_definition_inventory_for_blob_tx(
            tx,
            &blob.key.oid.to_string(),
            &blob.key.lang,
            blob.generation.0,
        )?;
        Ok((blob_id, surface_cost))
    }
}

/// Selected content admission uses the same planner as ordinary persistence.
/// Owner validation and the transaction belong to resolution_publication.
pub(super) fn publish_selected_source_tx(
    tx: &Transaction<'_>,
    prepared: &PreparedParsedBlob,
    cancellation: &CancellationToken,
) -> Result<i64> {
    let fragments = prepared.publication_fragments();
    let plans = prepare_publication_plans(tx, &fragments, &PreparedWriteCounters::default())?;
    let mut primary = None;
    for (fragment, plan) in fragments.into_iter().zip(plans) {
        let (id, _) = plan.publish(cancellation)?;
        if fragment.key() == &prepared.key {
            primary = Some(id);
        }
    }
    Ok(primary.expect("one primary source in the publication envelope"))
}

fn write_prepared_blob_rows_tx(
    publication: SourceReplacement<'_, '_>,
    cancellation: &CancellationToken,
) -> Result<i64> {
    let tx = publication.tx;
    let blob = publication.prepared;
    let generation = blob.generation;
    let oid_text = blob.key.oid.to_string();
    let oid = oid_text.as_str();
    let lang = blob.key.lang.as_str();
    // Every statement in this batch path is connection-cached: a cold reconcile
    // writes hundreds of blobs per transaction and re-preparing ~25 statements
    // per blob was a measured writer-CPU cost (issue #2326).
    //
    // The DELETE is what clears the blob's previous publication: every fact
    // table cascades from `blobs`, directly or through `code_units`,
    // `import_statements` or `blob_meta`. IDs remain database-owned. A Rust
    // repair preserves its ID when persisted crate rows retain references
    // to the same immutable content and epoch. Nothing outside SQLite holds
    // an ID across a query.
    let Some(previous_owners) =
        resolution_publication::repair_owners_tx(tx, &blob.key, generation, cancellation)?
    else {
        return Err(StoreError::cancelled(
            "prepared blob persistence was cancelled",
        ));
    };
    let previous_blob = if lang == "rust" {
        tx.prepare_cached(rust_crates::REPLACED_BLOB_ID_SQL)?
            .query_row(params![oid, lang, generation.0, blob.key.variant], |row| {
                row.get::<_, i64>(0)
            })
            .optional()?
    } else {
        None
    };
    if previous_blob.is_some() {
        // Crate rows retain blob IDs inside SQLite. A repair of the same
        // content and epoch preserves their facts and ID. Defer FK validation
        // across the delete/reinsert so the normal cascade clears damaged facts.
        tx.execute_batch("PRAGMA defer_foreign_keys = ON")?;
    }
    // The delete below cascades away the old row's unit summary members, exports
    // and imports, so the summaries that listed it stop being live first.
    {
        let _cascade = sealed_families::CascadeDelete::new(tx);
        tx.prepare_cached(unit_summaries::WITHDRAW_VERSIONS_OF_REPLACED_BLOB_SQL)?
            .execute(params![oid, lang, blob.key.variant])?;
    }
    csharp_compilation::extent::before_blob_delete(tx, &blob.key)?;
    // Only C# blobs carry condition symbols (asserted at the insert below), so
    // other languages issue no statement here.
    if lang == "csharp" {
        tx.execute(
            "DELETE FROM csharp_source_condition_symbols WHERE blob_id IN (
               SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2 AND parse_variant = ?3)",
            params![oid, lang, blob.key.variant],
        )?;

        tx.execute(
            csharp_compilation::DELETE_REPLACED_CHAINS_SQL,
            params![oid, lang, blob.key.variant],
        )?;
    }
    {
        let _cascade = sealed_families::CascadeDelete::new(tx);
        let removed = tx
            .prepare_cached(
                "DELETE FROM blobs WHERE blob_oid = ?1 AND lang = ?2 AND parse_variant = ?3
                 RETURNING generation",
            )?
            .query_map(params![oid, lang, blob.key.variant], |row| {
                row.get::<_, i64>(0)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        // The delete cascaded away the name rows of every file version that
        // mounts the old row, whether or not this publication restores the blob.
        for removed_generation in removed {
            brokk_bifrost_core::definition_inventory::withdraw_definition_inventory_for_deleted_blob_tx(
                tx,
                oid,
                lang,
                removed_generation,
                blob.key.variant,
            )?;
        }
    }
    tx.prepare_cached(rust_crates::REINSERT_BLOB_SQL)?
        .execute(params![
            previous_blob,
            oid,
            lang,
            generation.0,
            blob.key.variant
        ])?;
    let blob_id = tx.last_insert_rowid();
    assert!(
        lang == "csharp" || blob.csharp_condition_symbols.is_empty(),
        "only C# variants carry preprocessor symbols"
    );
    {
        let mut insert = tx.prepare_cached(
            "INSERT OR IGNORE INTO csharp_source_condition_symbols(blob_id, symbol) VALUES(?1, ?2)",
        )?;
        for symbol in &blob.csharp_condition_symbols {
            insert.execute(params![blob_id, symbol])?;
        }
    }
    assert!(lang == "csharp" || blob.csharp_undecided_scan.is_none());
    if lang == "csharp" && matches!(blob.key.variant, ParseVariant::Digest(_)) {
        let scan = blob
            .csharp_undecided_scan
            .as_ref()
            .expect("complete C# Digest publication requires a real undecided-chain scan");
        assert_eq!(scan.oid, blob.key.oid);
        assert_eq!(scan.variant, blob.key.variant);
    }
    let mut insert = tx.prepare_cached(csharp_compilation::INSERT_UNDECIDED_CHAIN_SQL)?;
    for row in blob
        .csharp_undecided_scan
        .iter()
        .flat_map(|scan| &scan.chains)
    {
        insert.execute(params![
            blob_id,
            row.chain,
            row.directive_start,
            row.directive_end,
            row.omitted_nonblank,
            row.invalid_condition,
            serde_json::to_vec(&row.unknown_symbols).expect("strings serialize"),
            serde_json::to_vec(&row.open_reasons).expect("strings serialize"),
            serde_json::to_vec(&row.disagreeing_owners).expect("strings serialize")
        ])?;
    }

    {
        // The only production writer of code_units. The scope ends before the
        // resolution bundle below, which opens its own owner scope.
        let _owner = sealed_families::Scope::new(tx, sealed_families::Owner::BlobRows);
        let mut stmt = tx.prepare_cached(
            "INSERT OR IGNORE INTO code_units(
               blob_id, lang, unit_key, kind, short_name, identifier, content_qualifier,
               exact_fqn, normalized_fqn, simple_type_name, signature, synthetic,
               is_type_alias, top_level_ordinal, in_declarations, in_definition_lookup,
               in_test_region, fq_segment_count, fq_segment_bytes,
               fq_anchor_kind, fq_anchor_pop,
               fq_package_tail_segments, exact_fqn_tail, normalized_fqn_tail,
               exact_parent_fqn_tail, normalized_parent_fqn_tail, package_fqn_tail
             ) VALUES(
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
               ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27
             )",
        )?;
        for row in &blob.units {
            stmt.execute(params![
                blob_id,
                lang,
                row.key,
                row.kind,
                row.short_name,
                row.identifier,
                row.content_qualifier,
                row.exact_fqn,
                row.normalized_fqn,
                row.simple_type_name,
                row.signature,
                row.synthetic,
                row.is_type_alias,
                row.top_level_ordinal,
                row.in_declarations,
                row.in_definition_lookup,
                row.in_test_region,
                row.fq_segment_count,
                row.fq_segment_bytes,
                row.fq_anchor_kind,
                row.fq_anchor_pop,
                row.fq_package_tail_segments,
                row.exact_fqn_tail,
                row.normalized_fqn_tail,
                row.exact_parent_fqn_tail,
                row.normalized_parent_fqn_tail,
                row.package_fqn_tail,
            ])?;
        }
    }
    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO code_unit_fq_segments(
               blob_id, lang, unit_key, seg_ordinal, seg_kind, segment
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for row in &blob.units {
            for (ordinal, kind, segment) in &row.relational_fq_segments {
                stmt.execute(params![blob_id, lang, row.key, ordinal, kind, segment])?;
            }
        }
    }
    macro_rules! insert_rows {
        ($sql:expr, $rows:expr, |$stmt:ident, $row:ident| $body:block) => {{
            let mut $stmt = tx.prepare_cached($sql)?;
            for $row in $rows $body
        }};
    }
    insert_rows!(
        "INSERT OR IGNORE INTO unit_ranges(blob_id, lang, unit_key, ordinal, start_byte, end_byte, start_line, end_line) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        &blob.ranges,
        |stmt, row| {
            stmt.execute(params![
                blob_id, lang, row.0, row.1, row.2, row.3, row.4, row.5
            ])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO unit_signatures(blob_id, lang, unit_key, ordinal, text) VALUES(?1, ?2, ?3, ?4, ?5)",
        &blob.signatures,
        |stmt, row| {
            stmt.execute(params![blob_id, lang, row.0, row.1, row.2])?;
        }
    );
    {
        let rows = blob
            .signature_metadata
            .iter()
            .map(|(unit_key, ordinal, metadata)| {
                metadata.bound_row(blob_id, lang, *unit_key, *ordinal)
            })
            .collect::<Vec<_>>();
        let (prefix, _) = signature_metadata_insert_sql()
            .split_once(" VALUES")
            .expect("signature metadata insert has a VALUES clause");
        let prefix = format!("{prefix} VALUES");
        let arity = 4 + SIGNATURE_METADATA_VALUE_COLUMNS.len();
        let row_sql = format!("({})", vec!["?"; arity].join(", "));
        source_facts::insert_rows(tx, &prefix, &row_sql, &rows, cancellation)?;
    }
    insert_rows!(
        "INSERT OR IGNORE INTO unit_signature_metadata_signatures(
           blob_id, unit_key, metadata_ordinal, signature_ordinal
         ) VALUES(?1, ?2, ?3, ?4)",
        &blob.signature_metadata_signature_ordinals,
        |stmt, row| {
            stmt.execute(params![blob_id, row.0, row.1, row.2])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO unit_supertypes(blob_id, lang, unit_key, ordinal, raw, lookup_path) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        &blob.supertypes,
        |stmt, row| {
            stmt.execute(params![blob_id, lang, row.0, row.1, row.2, row.3])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO unit_children(blob_id, lang, parent_key, child_key, ordinal) VALUES(?1, ?2, ?3, ?4, ?5)",
        &blob.children,
        |stmt, row| {
            stmt.execute(params![blob_id, lang, row.0, row.1, row.2])?;
        }
    );
    insert_import_rows(tx, blob_id, lang, &blob.imports)?;
    insert_rows!(
        "INSERT OR IGNORE INTO scala_exports(blob_id, lang, owner_key, ordinal, info) VALUES(?1, ?2, ?3, ?4, ?5)",
        &blob.scala_exports,
        |stmt, row| {
            stmt.execute(params![blob_id, lang, row.0, row.1, row.2])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO reference_identifiers(blob_id, lang, identifier) VALUES(?1, ?2, ?3)",
        &blob.type_identifiers,
        |stmt, row| {
            stmt.execute(params![blob_id, lang, row])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO ruby_method_dispatch_modes(blob_id, lang, unit_key, mode) VALUES(?1, ?2, ?3, ?4)",
        &blob.ruby_dispatch_modes,
        |stmt, row| {
            stmt.execute(params![blob_id, lang, row.0, row.1])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO materialization_records(blob_id, lang, ordinal, unit_key, payload) VALUES(?1, ?2, ?3, ?4, ?5)",
        &blob.materialization_records,
        |stmt, row| {
            stmt.execute(params![blob_id, lang, row.0, row.1, row.2])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO scala_traits(blob_id, lang, unit_key) VALUES(?1, ?2, ?3)",
        &blob.scala_traits,
        |stmt, row| {
            stmt.execute(params![blob_id, lang, row])?;
        }
    );
    insert_rust_fact_rows(tx, blob_id, lang, &blob.rust_facts)?;
    blob.cpp_templates.insert(tx, blob_id, cancellation)?;
    tx.prepare_cached("INSERT OR IGNORE INTO reference_fact_epochs(lang, epoch) VALUES(?1, 1)")?
        .execute([lang])?;
    tx.prepare_cached(
        "INSERT INTO blob_reference_fact_manifests(blob_id, lang, epoch, identifier_count)
         VALUES(?1, ?2, 1, ?3)
         ON CONFLICT(blob_id) DO UPDATE SET
           epoch = excluded.epoch,
           identifier_count = excluded.identifier_count",
    )?
    .execute(params![
        blob_id,
        lang,
        usize_to_i64(blob.type_identifiers.len())?
    ])?;
    tx.prepare_cached(
        "INSERT OR IGNORE INTO blob_meta(
           blob_id, lang, contains_tests, content_package, stored_unit_count,
           range_count, signature_count, signature_metadata_count, supertype_count,
           child_count, import_statement_count, type_identifier_count, is_complete,
           declaration_visibility_version, java_type_constructor_version, go_source_version, java_source_version, scala_source_version, ruby_source_version, php_source_version, cpp_source_version, source_facts_version, metadata_bridges_required, js_ts_source_version, python_source_version, native_bridges_required, parse_completeness
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26)",
    )?
    .execute(params![
        blob_id,
        lang,
        blob.contains_tests,
        blob.content_package,
        usize_to_i64(blob.units.len())?,
        usize_to_i64(blob.ranges.len())?,
        usize_to_i64(blob.signatures.len())?,
        usize_to_i64(blob.signature_metadata.len())?,
        usize_to_i64(blob.supertypes.len())?,
        usize_to_i64(blob.children.len())?,
        usize_to_i64(blob.imports.statements.len())?,
        usize_to_i64(blob.type_identifiers.len())?,
        blob.declaration_visibility_version,
        blob.java_type_constructor_version,
        blob.go_source_version,
        blob.java_source_version,
        blob.scala_source_version,
        blob.ruby_source_version,
        blob.php_source_version,
        blob.cpp_source_version,
        blob.source_facts_version,
        blob.metadata_bridges_required,
        blob.js_ts_source_version,
        blob.python_source_version,
        blob.source_facts_version.is_some(),
        blob.state.completeness.label(),
    ])?;
    insert_optional_fact_manifest(
        tx,
        blob_id,
        optional_fact_counts(
            blob.cpp_templates.header_count(),
            blob.ruby_dispatch_modes.len(),
            blob.scala_traits.len(),
            blob.scala_exports.len(),
            blob.materialization_records.len(),
            blob.signature_metadata_signature_ordinals.len(),
        ),
    )?;
    let integrity_condition = PARSED_BLOB_STRUCTURAL_INTEGRITY_CONDITION.as_str();
    let integrity_sql = format!(
        "SELECT 1 FROM blob_meta AS meta
         WHERE meta.blob_id = ?1
           AND {integrity_condition}"
    );
    let complete = tx
        .prepare_cached(&integrity_sql)?
        .query_row(params![blob_id], |_| Ok(()))
        .optional()?
        .is_some();
    if !complete {
        return Err(StoreError::new(format!(
            "prepared blob {oid}/{lang} failed post-write integrity validation"
        )));
    }
    if let Some(facts) = blob.state.source_facts.as_ref() {
        source_facts::insert_source_facts_tx(
            blob.source_storage,
            tx,
            blob_id,
            facts,
            &blob.source_declaration_units,
            &blob.source_declaration_metadata,
            cancellation,
        )?;
    }
    if !resolution::insert_prepared_bundle_tx(tx, blob_id, lang, &blob.resolution, cancellation)? {
        return Err(StoreError::cancelled(
            "prepared blob persistence was cancelled",
        ));
    }
    if let Some(semantic_ir) = blob.semantic_ir.as_ref()
        && !insert_semantic_ir_tx(tx, blob_id, lang, semantic_ir, cancellation)?
    {
        return Err(StoreError::cancelled(
            "prepared blob persistence was cancelled",
        ));
    }
    let source_ready: bool = tx.query_row(
        "SELECT available FROM source_fact_readiness WHERE blob_id = ?1",
        [blob_id],
        |row| row.get(0),
    )?;
    if !source_ready {
        return Err(StoreError::new(format!(
            "prepared blob {oid}/{lang} has unavailable canonical source facts"
        )));
    }
    if let Some(version) = blob.cpp_source_version {
        let cpp_ready: bool = tx.query_row(
            "SELECT EXISTS(
               SELECT 1 FROM source_cpp_manifests AS marker
               JOIN source_fact_manifests AS source ON source.blob_id = marker.blob_id
               WHERE marker.blob_id = ?1 AND marker.facts_version = ?2
                 AND source.publication_state = 'complete'
             )",
            params![blob_id, version],
            |row| row.get(0),
        )?;
        if !cpp_ready {
            return Err(StoreError::new(format!(
                "prepared blob {oid}/{lang} has unavailable C++ source facts"
            )));
        }
    }
    let resolution_payload_bytes: usize = tx.query_row(
        "SELECT payload_bytes FROM resolution_fragment_interiors WHERE blob_id = ?1",
        [blob_id],
        |row| row.get(0),
    )?;
    let persisted_payload_bytes = blob
        .persisted_payload_bytes()
        .checked_sub(
            blob.resolution
                .payload_bytes()
                .saturating_add(blob.key.lang.len()),
        )
        .expect("parsed publication includes its resolution estimate and storage language")
        .saturating_add(resolution_payload_bytes);
    insert_blob_payload_cost_tx(tx, blob_id, persisted_payload_bytes)?;
    for owner in &previous_owners {
        resolution_publication::root_content_tx(tx, owner, blob_id)?;
    }
    Ok(blob_id)
}
