//! Republish producer products without replacing a healthy canonical source.

use super::*;

/// Authority to retain one exact canonical source publication. This proves no
/// resolution or IR product: those have independent producer epochs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct SourcePublicationWitness {
    key: BlobKey,
    generation: GenerationId,
    blob_id: i64,
    publication_witness: i64,
    store_nonce: Vec<u8>,
}

const SOURCE_PUBLICATION_SQL: &str = "SELECT blob.id, blob.generation,
       meta.publication_witness, sequence.store_nonce
     FROM blobs AS blob
     JOIN blob_meta AS meta ON meta.blob_id = blob.id AND meta.is_complete = 1
     JOIN source_fact_readiness AS readiness
       ON readiness.blob_id = blob.id AND readiness.available = 1
     JOIN blob_publication_witness_sequence AS sequence ON sequence.id = 1
     WHERE blob.blob_oid = ?1 AND blob.lang = ?2 AND blob.parse_variant = ?3
       AND blob.generation = COALESCE(
         (SELECT generation FROM analysis_epochs WHERE lang = ?2), 0)
       AND meta.publication_witness IS NOT NULL";

pub(super) fn source_publications_conn(
    conn: &Connection,
    keys: &[BlobKey],
) -> Result<HashMap<BlobKey, SourcePublicationWitness>> {
    sync_requested_parsed_blobs(conn, keys)?;
    let mut statement = conn.prepare_cached(
        "SELECT requested.blob_oid, requested.lang, requested.parse_variant,
                blob.id, blob.generation, meta.publication_witness, sequence.store_nonce
         FROM temp.requested_parsed_blobs AS requested
         JOIN blobs AS blob ON blob.blob_oid = requested.blob_oid
           AND blob.lang = requested.lang AND blob.parse_variant = requested.parse_variant
           AND blob.generation = COALESCE(
             (SELECT generation FROM analysis_epochs WHERE lang = requested.lang), 0)
         JOIN blob_meta AS meta ON meta.blob_id = blob.id AND meta.is_complete = 1
         JOIN source_fact_readiness AS readiness
           ON readiness.blob_id = blob.id AND readiness.available = 1
         JOIN blob_publication_witness_sequence AS sequence ON sequence.id = 1
         WHERE meta.publication_witness IS NOT NULL",
    )?;
    let mut rows = statement.query([])?;
    let mut witnesses = HashMap::default();
    while let Some(row) = rows.next()? {
        let oid: String = row.get(0)?;
        let key = BlobKey {
            oid: Oid::from_str(&oid).map_err(|error| StoreError::corrupt(error.to_string()))?,
            lang: row.get(1)?,
            variant: row.get(2)?,
        };
        let witness = SourcePublicationWitness {
            key: key.clone(),
            blob_id: row.get(3)?,
            generation: GenerationId(row.get(4)?),
            publication_witness: row.get(5)?,
            store_nonce: row.get(6)?,
        };
        witnesses.insert(key, witness);
    }
    Ok(witnesses)
}

impl SourcePublicationWitness {
    pub(super) fn key(&self) -> &BlobKey {
        &self.key
    }

    pub(super) fn generation(&self) -> GenerationId {
        self.generation
    }

    pub(super) fn blob_id(&self) -> i64 {
        self.blob_id
    }

    pub(super) fn read(conn: &Connection, key: &BlobKey) -> Result<Option<Self>> {
        Ok(conn
            .prepare_cached(SOURCE_PUBLICATION_SQL)?
            .query_row(params![key.oid.to_string(), key.lang, key.variant], |row| {
                Ok(Self {
                    key: key.clone(),
                    blob_id: row.get(0)?,
                    generation: GenerationId(row.get(1)?),
                    publication_witness: row.get(2)?,
                    store_nonce: row.get(3)?,
                })
            })
            .optional()?)
    }

    fn validate(&self, tx: &Transaction<'_>) -> Result<()> {
        if Self::read(tx, &self.key)?.as_ref() != Some(self) {
            return Err(StoreError::stale_resolution(format!(
                "canonical source publication moved before derived publication: {:?}",
                self.key
            )));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct PreparedDerivedBlob {
    source: SourcePublicationWitness,
    state: Arc<FileState>,
    resolution: PreparedResolutionBundle,
    semantic_ir: Option<PreparedSemanticIr>,
    canonical_payload_bytes: usize,
    retained_payload_bytes: usize,
}

#[derive(Debug)]
enum PreparedPublicationFragment {
    Source(Box<PreparedParsedBlob>),
    Derived(Box<PreparedDerivedBlob>),
}

/// An atomic source variant with independently classified storage projections.
/// Missing or damaged canonical source uses the ordinary full-source payload.
#[derive(Debug)]
#[doc(hidden)]
pub struct PreparedAnalysisPublication {
    fragments: Vec<PreparedPublicationFragment>,
}

impl PreparedAnalysisPublication {
    #[doc(hidden)]
    pub fn key(&self) -> &BlobKey {
        PreparedPersistenceEnvelope::key(self)
    }
    #[doc(hidden)]
    pub fn state(&self) -> &Arc<FileState> {
        match &self.fragments[0] {
            PreparedPublicationFragment::Source(blob) => &blob.state,
            PreparedPublicationFragment::Derived(blob) => &blob.state,
        }
    }
    #[doc(hidden)]
    pub fn logical_rows(&self) -> usize {
        saturating_sum(
            self.publication_fragments()
                .into_iter()
                .map(PreparedPublicationRef::logical_rows),
        )
    }
    #[doc(hidden)]
    pub fn payload_bytes(&self) -> usize {
        saturating_sum(
            self.publication_fragments()
                .into_iter()
                .map(PreparedPublicationRef::payload_bytes),
        )
    }
    #[doc(hidden)]
    pub fn mutation_payload_bytes(&self) -> usize {
        saturating_sum(self.fragments.iter().map(|fragment| match fragment {
            PreparedPublicationFragment::Source(blob) => blob.mutation_payload_bytes(),
            PreparedPublicationFragment::Derived(blob) => blob.retained_payload_bytes,
        }))
    }
}

impl PreparedParsedBlob {
    pub(super) fn canonical_payload_bytes(&self) -> usize {
        self.persisted_payload_bytes()
            .checked_sub(self.resolution.payload_bytes() + self.key.lang.len())
            .and_then(|bytes| {
                bytes.checked_sub(
                    self.semantic_ir
                        .as_ref()
                        .map_or(0, PreparedSemanticIr::payload_bytes),
                )
            })
            .expect("prepared payload includes resolution and IR estimates")
    }

    #[doc(hidden)]
    pub fn preserve_source_publications(
        mut self,
        sources: &[SourcePublicationWitness],
    ) -> PreparedAnalysisPublication {
        let additional = std::mem::take(&mut self.additional);
        assert!(
            additional
                .iter()
                .all(|fragment| fragment.source_variant() == self.source_variant())
        );
        assert!(
            additional
                .iter()
                .all(|fragment| fragment.additional.is_empty())
        );
        let fragments = std::iter::once(self)
            .chain(additional)
            .map(|blob| {
                let Some(source) = sources.iter().find(|source| source.key == blob.key) else {
                    return PreparedPublicationFragment::Source(Box::new(blob));
                };
                assert_eq!(source.generation, blob.generation);
                let canonical_payload_bytes = blob.canonical_payload_bytes();
                PreparedPublicationFragment::Derived(Box::new(PreparedDerivedBlob {
                    source: source.clone(),
                    state: blob.state,
                    resolution: blob.resolution,
                    semantic_ir: blob.semantic_ir,
                    canonical_payload_bytes,
                    retained_payload_bytes: blob.payload_bytes,
                }))
            })
            .collect();
        PreparedAnalysisPublication { fragments }
    }
}

#[derive(Clone, Copy)]
pub(super) enum PreparedPublicationRef<'a> {
    Source(&'a PreparedParsedBlob),
    Repair(super::source_publication::ExplicitRepairRef<'a>),
    Derived(&'a PreparedDerivedBlob),
}

impl<'a> PreparedPublicationRef<'a> {
    pub(super) fn key(self) -> &'a BlobKey {
        match self {
            Self::Source(blob) => &blob.key,
            Self::Repair(repair) => &repair.prepared().key,
            Self::Derived(blob) => &blob.source.key,
        }
    }
    pub(super) fn lang(self) -> &'a str {
        &self.key().lang
    }
    pub(super) fn generation(self) -> GenerationId {
        match self {
            Self::Source(blob) => blob.generation,
            Self::Repair(repair) => repair.prepared().generation,
            Self::Derived(blob) => blob.source.generation,
        }
    }
    pub(super) fn resolution(self) -> &'a PreparedResolutionBundle {
        match self {
            Self::Source(blob) => &blob.resolution,
            Self::Repair(repair) => &repair.prepared().resolution,
            Self::Derived(blob) => &blob.resolution,
        }
    }
    pub(super) fn semantic_ir(self) -> Option<&'a PreparedSemanticIr> {
        match self {
            Self::Source(blob) => blob.semantic_ir.as_ref(),
            Self::Repair(repair) => repair.prepared().semantic_ir.as_ref(),
            Self::Derived(blob) => blob.semantic_ir.as_ref(),
        }
    }
    pub(super) fn logical_rows(self) -> usize {
        match self {
            Self::Source(blob) => blob.logical_rows(),
            Self::Repair(repair) => repair.prepared().logical_rows(),
            Self::Derived(blob) => blob.resolution.logical_rows().saturating_add(
                blob.semantic_ir
                    .as_ref()
                    .map_or(0, PreparedSemanticIr::logical_rows),
            ),
        }
    }
    pub(super) fn payload_bytes(self) -> usize {
        match self {
            Self::Source(blob) => blob.payload_bytes(),
            Self::Repair(repair) => repair.prepared().payload_bytes(),
            Self::Derived(blob) => blob.resolution.payload_bytes().saturating_add(
                blob.semantic_ir
                    .as_ref()
                    .map_or(0, PreparedSemanticIr::payload_bytes),
            ),
        }
    }
    pub(super) fn grouping_cost(self) -> super::PersistedMutationCost {
        match self {
            Self::Source(blob) => blob.grouping_cost(),
            Self::Repair(repair) => repair.prepared().grouping_cost(),
            Self::Derived(_) => super::PersistedMutationCost {
                logical_rows: self.logical_rows(),
                payload_bytes: self.payload_bytes(),
            },
        }
    }
    pub(super) fn has_same_persisted_fragment(self, other: Self) -> bool {
        match (self, other) {
            (Self::Source(left), Self::Source(right)) => left.has_same_persisted_fragment(right),
            (Self::Repair(left), Self::Repair(right)) => left
                .prepared()
                .has_same_persisted_fragment(right.prepared()),
            (Self::Derived(left), Self::Derived(right)) => {
                left.source == right.source
                    && left.resolution == right.resolution
                    && left.semantic_ir == right.semantic_ir
                    && left.canonical_payload_bytes == right.canonical_payload_bytes
            }
            _ => false,
        }
    }
}

pub(super) trait PreparedPersistenceEnvelope: Send + 'static {
    fn fragment_count(&self) -> usize;
    fn fragment_at(&self, ordinal: usize) -> PreparedPublicationRef<'_>;
    fn publication_fragments(&self) -> Vec<PreparedPublicationRef<'_>> {
        (0..self.fragment_count())
            .map(|ordinal| self.fragment_at(ordinal))
            .collect()
    }
    fn key(&self) -> &BlobKey {
        self.fragment_at(0).key()
    }
    fn source_variant(&self) -> (Oid, ParseVariant) {
        (self.key().oid, self.key().variant)
    }
    fn oid(&self) -> Oid {
        self.key().oid
    }
    fn lang(&self) -> &str {
        &self.key().lang
    }
}

impl PreparedPersistenceEnvelope for PreparedParsedBlob {
    fn fragment_count(&self) -> usize {
        self.fragment_count()
    }
    fn fragment_at(&self, ordinal: usize) -> PreparedPublicationRef<'_> {
        PreparedPublicationRef::Source(self.fragment_at(ordinal))
    }
    fn publication_fragments(&self) -> Vec<PreparedPublicationRef<'_>> {
        let mut fragments = Vec::with_capacity(self.fragment_count());
        self.append_fragments(&mut fragments);
        fragments
            .into_iter()
            .map(PreparedPublicationRef::Source)
            .collect()
    }
}

impl PreparedPersistenceEnvelope for PreparedAnalysisPublication {
    fn fragment_count(&self) -> usize {
        self.fragments.len()
    }
    fn fragment_at(&self, ordinal: usize) -> PreparedPublicationRef<'_> {
        match &self.fragments[ordinal] {
            PreparedPublicationFragment::Source(blob) => PreparedPublicationRef::Source(blob),
            PreparedPublicationFragment::Derived(blob) => PreparedPublicationRef::Derived(blob),
        }
    }
}

/// Each product is independently replaceable. `None` means an existing current
/// complete head needs no writes; a missing head has a zero previous cost.
pub(super) struct DerivedReplacement {
    resolution: Option<PersistedMutationCost>,
    semantic_ir: Option<PersistedMutationCost>,
}

pub(super) struct DerivedProducts<'a> {
    source: &'a SourcePublicationWitness,
    state: &'a FileState,
    resolution: &'a PreparedResolutionBundle,
    semantic_ir: Option<&'a PreparedSemanticIr>,
    canonical_payload_bytes: usize,
}

impl PreparedDerivedBlob {
    pub(super) fn products(&self) -> DerivedProducts<'_> {
        DerivedProducts {
            source: &self.source,
            state: self.state.as_ref(),
            resolution: &self.resolution,
            semantic_ir: self.semantic_ir.as_ref(),
            canonical_payload_bytes: self.canonical_payload_bytes,
        }
    }
}

impl<'a> DerivedProducts<'a> {
    pub(super) fn from_parsed(
        source: &'a SourcePublicationWitness,
        blob: &'a PreparedParsedBlob,
    ) -> Self {
        assert_eq!(source.key, blob.key);
        assert_eq!(source.generation, blob.generation);
        Self {
            source,
            state: blob.state.as_ref(),
            resolution: &blob.resolution,
            semantic_ir: blob.semantic_ir.as_ref(),
            canonical_payload_bytes: blob.canonical_payload_bytes(),
        }
    }
    pub(super) fn source(&self) -> &SourcePublicationWitness {
        self.source
    }

    pub(super) fn replacement(&self, tx: &Transaction<'_>) -> Result<DerivedReplacement> {
        self.source.validate(tx)?;
        let resolution = tx
            .query_row(
                "SELECT producer_epoch, publication_state, logical_rows, payload_bytes
             FROM resolution_fragment_interiors WHERE blob_id = ?1",
                [self.source.blob_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        PersistedMutationCost {
                            logical_rows: row.get(2)?,
                            payload_bytes: row.get(3)?,
                        },
                    ))
                },
            )
            .optional()?;
        let native_current = store_language_support(self.resolution.semantic_language())
            .map(|support| support.native_resolution_rows_current(tx, self.source.blob_id))
            .transpose()?
            .unwrap_or(true);
        let resolution = match resolution {
            Some((epoch, state, _))
                if epoch == self.resolution.producer_epoch()
                    && state == "complete"
                    && native_current =>
            {
                None
            }
            old => Some(old.map_or(PersistedMutationCost::default(), |(_, _, cost)| cost)),
        };
        let semantic_ir = if let Some(prepared) = &self.semantic_ir {
            let previous = tx
                .query_row(
                    "SELECT producer_epoch, publication_state, logical_rows, payload_bytes
                 FROM semantic_ir_publications WHERE blob_id = ?1",
                    [self.source.blob_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            PersistedMutationCost {
                                logical_rows: row.get(2)?,
                                payload_bytes: row.get(3)?,
                            },
                        ))
                    },
                )
                .optional()?;
            match previous {
                Some((epoch, state, _))
                    if epoch == prepared.producer_epoch() && state == "complete" =>
                {
                    None
                }
                old => Some(old.map_or(PersistedMutationCost::default(), |(_, _, cost)| cost)),
            }
        } else {
            None
        };
        Ok(DerivedReplacement {
            resolution,
            semantic_ir,
        })
    }

    /// Total payload bytes of the Source plus its stored resolution and IR rows.
    fn expected_payload_bytes(&self, tx: &Transaction<'_>) -> Result<i64> {
        let blob_id = self.source.blob_id;
        let resolution_bytes: usize = tx.query_row(
            "SELECT payload_bytes FROM resolution_fragment_interiors WHERE blob_id = ?1",
            [blob_id],
            |row| row.get(0),
        )?;
        let semantic_bytes: usize = tx.query_row(
            "SELECT COALESCE((SELECT payload_bytes FROM semantic_ir_publications WHERE blob_id = ?1), 0)",
            [blob_id], |row| row.get(0),
        )?;
        usize_to_i64(
            self.canonical_payload_bytes
                .saturating_add(resolution_bytes)
                .saturating_add(semantic_bytes),
        )
    }

    pub(super) fn publish(
        &self,
        tx: &Transaction<'_>,
        replacement: DerivedReplacement,
        cancellation: &CancellationToken,
    ) -> Result<PersistedMutationCost> {
        if replacement.resolution.is_none() && replacement.semantic_ir.is_none() {
            // Adopting a healthy Source writes nothing; a missing or corrupt
            // cost row is repaired (with its cascade cache) only when it differs.
            let blob_id = self.source.blob_id;
            let expected = self.expected_payload_bytes(tx)?;
            let current: Option<i64> = tx
                .query_row(
                    "SELECT payload_bytes FROM blob_payload_costs WHERE blob_id = ?1",
                    [blob_id],
                    |row| row.get(0),
                )
                .optional()?;
            if current != Some(expected) {
                tx.execute(
                    "INSERT INTO blob_payload_costs(blob_id, payload_bytes) VALUES(?1, ?2)
                     ON CONFLICT(blob_id) DO UPDATE SET payload_bytes = excluded.payload_bytes",
                    params![blob_id, expected],
                )?;
                tx.execute("UPDATE blobs SET cascade_logical_rows = NULL, cascade_payload_bytes = NULL WHERE id = ?1", [blob_id])?;
            }
            let (_, cost) =
                surface_relations::ensure_surface_set_for_publication_tx(tx, self.source)?;
            return Ok(cost);
        }
        if cancellation.is_cancelled() {
            return Err(StoreError::cancelled("derived publication was cancelled"));
        }
        let blob_id = self.source.blob_id;
        let key = &self.source.key;
        if replacement.resolution.is_some() {
            {
                let _cascade = sealed_families::CascadeDelete::new(tx);
                if let Some(support) = store_language_support(self.resolution.semantic_language()) {
                    support.retire_native_resolution_rows(tx, blob_id)?;
                }
            }
            {
                let _cascade = sealed_families::CascadeDelete::new(tx);
                tx.prepare_cached(unit_summaries::WITHDRAW_VERSIONS_OF_REPLACED_BLOB_SQL)?
                    .execute(params![key.oid.to_string(), key.lang, key.variant])?;
            }
            csharp_compilation::extent::before_blob_delete(tx, key)?;
            {
                let _cascade = sealed_families::CascadeDelete::new(tx);
                tx.execute(
                    "DELETE FROM resolution_fragment_interiors WHERE blob_id = ?1",
                    [blob_id],
                )?;
            }
            if !resolution::insert_prepared_bundle_tx(
                tx,
                blob_id,
                &key.lang,
                self.resolution,
                cancellation,
            )? {
                return Err(StoreError::cancelled(
                    "derived resolution publication was cancelled",
                ));
            }
            if let Some(support) = store_language_support(self.resolution.semantic_language()) {
                support.publish_native_resolution_rows(
                    tx,
                    blob_id,
                    &self.state.resolution_facts,
                    cancellation,
                )?;
            }
        }
        if replacement.semantic_ir.is_some() {
            tx.execute(
                "DELETE FROM semantic_ir_publications WHERE blob_id = ?1",
                [blob_id],
            )?;
            if !insert_semantic_ir_tx(
                tx,
                blob_id,
                &key.lang,
                self.semantic_ir
                    .as_ref()
                    .expect("IR replacement has prepared rows"),
                cancellation,
            )? {
                return Err(StoreError::cancelled(
                    "derived IR publication was cancelled",
                ));
            }
        }
        let payload_bytes = self.expected_payload_bytes(tx)?;
        tx.execute(
            "INSERT INTO blob_payload_costs(blob_id, payload_bytes) VALUES(?1, ?2)
             ON CONFLICT(blob_id) DO UPDATE SET payload_bytes = excluded.payload_bytes",
            params![blob_id, payload_bytes],
        )?;
        // Cached cascade costs cover the old derived products, so invalidate the
        // accounting cache without changing the source's publication witness.
        tx.execute("UPDATE blobs SET cascade_logical_rows = NULL, cascade_payload_bytes = NULL WHERE id = ?1", [blob_id])?;
        let (_, surface_cost) =
            surface_relations::ensure_surface_set_for_publication_tx(tx, self.source)?;
        csharp_compilation::extent::content_available(tx, &key.lang, blob_id)?;
        Ok(surface_cost)
    }
}

impl DerivedReplacement {
    pub(super) fn cost(&self, blob: &DerivedProducts<'_>) -> PersistedMutationCost {
        let mut cost = PersistedMutationCost::default();
        if let Some(old) = self.resolution {
            cost.logical_rows = old
                .logical_rows
                .saturating_add(blob.resolution.logical_rows());
            cost.payload_bytes = old
                .payload_bytes
                .saturating_add(blob.resolution.payload_bytes());
        }
        if let Some(old) = self.semantic_ir {
            let prepared = blob
                .semantic_ir
                .as_ref()
                .expect("IR replacement has prepared rows");
            cost.logical_rows = cost
                .logical_rows
                .saturating_add(old.logical_rows)
                .saturating_add(prepared.logical_rows());
            cost.payload_bytes = cost
                .payload_bytes
                .saturating_add(old.payload_bytes)
                .saturating_add(prepared.payload_bytes());
        }
        if self.resolution.is_some() || self.semantic_ir.is_some() {
            cost.logical_rows = cost.logical_rows.saturating_add(2);
        }
        cost
    }
}

impl AnalyzerStore {
    #[doc(hidden)]
    pub fn persist_prepared_analysis_publications_with_cancellation(
        &self,
        prepared: Vec<PreparedAnalysisPublication>,
        cancellation: &CancellationToken,
        limits: PersistBatchTargets,
    ) -> (
        Vec<PersistPreparedOutcome<PreparedAnalysisPublication>>,
        PersistBatchStats,
    ) {
        let counters = self.prepared_write_counters();
        let cancellation = cancellation.clone();
        self.conn.execute(move |conn| {
            PreparedPersistenceWriter::new(conn, counters, cancellation)
                .persist_prepared_blobs(prepared, limits)
        })
    }
}
