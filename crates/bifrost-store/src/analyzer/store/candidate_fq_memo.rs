//! Candidate FQ identities reused across the relational batches of one outer
//! query (#8826).
//!
//! One request can run many relational batches that select the same candidate
//! units, and each batch used to load the same `code_unit_fq_segments` rows
//! again. The memo keeps each validated identity for the rest of the outer
//! query. A hit needs all of these to agree with the candidate row that the
//! current batch selected:
//!
//! - The persisted publication witness. `blob_meta.publication_witness` is
//!   minted by trigger each time a blob row becomes complete, from a sequence
//!   that never repeats within one database lineage. The seal triggers on
//!   `code_unit_fq_segments` reject every change to the FQ rows of a complete
//!   blob except the cascade that deletes the blob, so an equal witness means
//!   unchanged FQ rows.
//! - The database lineage (`store_nonce`) and the language generation that the
//!   batch validated. The generation covers the FQ producer, because a
//!   language's epoch changes when its emitted identities do.
//! - The whole selected FQ header. Headers live on `code_units` and are not
//!   sealed, so a different header is a miss, not corruption.
//!
//! No entry records an absent, incomplete or cancelled identity, and nothing
//! outside the caller's outer query holds the memo.

use std::sync::Mutex;
#[cfg(any(test, feature = "test-support"))]
use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::Connection;

use super::selected_read_memo::ExactReadMemo;
use super::{
    BlobKey, CandidateRow, CandidateRowContainer, FqIdentityHeader, GenerationId, RelationalUnitFq,
    Result, StoreError, attach_complete_relational_fq, hydrate_candidate_rows,
};
use crate::analyzer::fq_name::SegmentKind;
use crate::hash::HashMap;

type CandidateKey = (BlobKey, i64);

struct CandidateFqEntry {
    store_nonce: [u8; 16],
    generation: GenerationId,
    witness: i64,
    header: Option<FqIdentityHeader>,
    segments: Vec<(SegmentKind, String)>,
}

impl CandidateFqEntry {
    fn matches(
        &self,
        store_nonce: &[u8; 16],
        generation: GenerationId,
        witness: i64,
        header: &Option<FqIdentityHeader>,
    ) -> bool {
        self.store_nonce == *store_nonce
            && self.generation == generation
            && self.witness == witness
            && self.header == *header
    }

    /// Estimated heap bytes, charged against the memo's byte cap.
    fn weight(&self, key: &CandidateKey) -> usize {
        let header = self.header.as_ref().map_or(0, |header| {
            header.exact_tail.len() + header.normalized_tail.as_ref().map_or(0, String::len)
        });
        let segments = self
            .segments
            .iter()
            .map(|(_, segment)| std::mem::size_of::<(SegmentKind, String)>() + segment.len())
            .sum::<usize>();
        std::mem::size_of::<CandidateKey>()
            + std::mem::size_of::<Self>()
            + key.0.lang.len()
            + header
            + segments
    }
}

/// Validated candidate FQ identities for one outer query. The analyzer owns one
/// per outer query scope and passes it to each relational store read.
pub struct CandidateFqMemo {
    entries: Mutex<ExactReadMemo<CandidateKey, CandidateFqEntry>>,
    #[cfg(any(test, feature = "test-support"))]
    hits: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    hydrated_keys: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    peak_staged_entries: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    peak_staged_bytes: AtomicUsize,
}

impl Default for CandidateFqMemo {
    fn default() -> Self {
        Self::with_entries(ExactReadMemo::default())
    }
}

/// Test view of a memo's work.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateFqMemoCounts {
    /// Candidate rows served without reading FQ segments.
    pub hits: usize,
    /// Candidate keys whose FQ segments a batch read. A key that its batch
    /// could not stage under the caps counts again when it is reread.
    pub hydrated_keys: usize,
    /// The most entries one batch held staged at once.
    pub peak_staged_entries: usize,
    /// The most bytes one batch held staged at once.
    pub peak_staged_bytes: usize,
    /// Admissions refused by the entry or byte cap.
    pub refused_admissions: usize,
    /// Entries currently held.
    pub entries: usize,
    /// Bytes charged against the byte cap.
    pub weighed_bytes: usize,
    /// The estimate recomputed from the entries held now.
    pub held_bytes: usize,
}

impl CandidateFqMemo {
    fn with_entries(entries: ExactReadMemo<CandidateKey, CandidateFqEntry>) -> Self {
        Self {
            entries: Mutex::new(entries),
            #[cfg(any(test, feature = "test-support"))]
            hits: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            hydrated_keys: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            peak_staged_entries: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            peak_staged_bytes: AtomicUsize::new(0),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn with_caps_for_test(entry_cap: usize, byte_cap: usize) -> Self {
        Self::with_entries(ExactReadMemo::with_caps(entry_cap, byte_cap))
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn counts_for_test(&self) -> CandidateFqMemoCounts {
        let entries = self.entries.lock().expect("candidate FQ memo poisoned");
        CandidateFqMemoCounts {
            hits: self.hits.load(Ordering::Relaxed),
            hydrated_keys: self.hydrated_keys.load(Ordering::Relaxed),
            peak_staged_entries: self.peak_staged_entries.load(Ordering::Relaxed),
            peak_staged_bytes: self.peak_staged_bytes.load(Ordering::Relaxed),
            refused_admissions: entries.bounded_counts().1,
            entries: entries.iter().count(),
            weighed_bytes: entries.weighed_bytes(),
            held_bytes: entries.iter().map(|(key, entry)| entry.weight(key)).sum(),
        }
    }
}

/// The memo as one relational batch sees it: the lineage and generations that
/// the batch validated, and the identities it read, which join the memo only
/// when the batch completes.
pub(super) struct CandidateFqBatch<'a> {
    memo: &'a CandidateFqMemo,
    store_nonce: [u8; 16],
    generations: &'a HashMap<String, GenerationId>,
    /// Bounded by the memo's own caps. One batch runs many statements, so
    /// past the caps a hydrated identity goes to its caller without being
    /// kept, and a later miss rereads it.
    staged: ExactReadMemo<CandidateKey, CandidateFqEntry>,
}

/// A candidate row the memo could not serve, waiting for its FQ segments.
struct Miss<T> {
    index: usize,
    witness: i64,
    generation: GenerationId,
    row: T,
}

/// A missed row after hydration, with the identity it adds to the batch.
struct Loaded<H> {
    index: usize,
    witness: i64,
    generation: GenerationId,
    key: CandidateKey,
    header: Option<FqIdentityHeader>,
    segments: Vec<(SegmentKind, String)>,
    row: H,
}

fn candidate_key(candidate: &CandidateRow) -> CandidateKey {
    (
        BlobKey {
            oid: candidate.blob_oid,
            lang: candidate.lang.clone(),
            variant: candidate.variant,
        },
        candidate.unit_key,
    )
}

impl<T: CandidateRowContainer> CandidateRowContainer for Miss<T> {
    type Hydrated = Loaded<T::Hydrated>;

    fn candidate(&self) -> &CandidateRow {
        self.row.candidate()
    }

    fn with_hydrated_fq(self, fq: Option<RelationalUnitFq>) -> Self::Hydrated {
        let candidate = self.row.candidate();
        let key = candidate_key(candidate);
        let header = candidate.fq.clone();
        let segments = fq
            .as_ref()
            .map(|fq| fq.segments.clone())
            .unwrap_or_default();
        Loaded {
            index: self.index,
            witness: self.witness,
            generation: self.generation,
            key,
            header,
            segments,
            row: self.row.with_hydrated_fq(fq),
        }
    }
}

impl<'a> CandidateFqBatch<'a> {
    /// Start the memo's view of one batch. Call on the batch transaction after
    /// `require_generation_map` has validated `generations`.
    pub(super) fn begin(
        tx: &Connection,
        memo: &'a CandidateFqMemo,
        generations: &'a HashMap<String, GenerationId>,
    ) -> Result<Self> {
        // The nonce names one database lineage, and a copy of the file keeps
        // it. Stores open versioned files and migrate them before opening;
        // replacing a cache file that live queries are reading is outside the
        // supported access contract. So equal nonces mean one lineage.
        let nonce: Vec<u8> = tx
            .prepare_cached(
                "SELECT store_nonce FROM blob_publication_witness_sequence WHERE id = 1",
            )?
            .query_row([], |row| row.get(0))?;
        let store_nonce = <[u8; 16]>::try_from(nonce.as_slice()).map_err(|_| {
            StoreError::new(format!(
                "analyzer store publication witness nonce has {} bytes, expected 16",
                nonce.len()
            ))
        })?;
        let staged = memo
            .entries
            .lock()
            .expect("candidate FQ memo poisoned")
            .empty_with_same_caps();
        Ok(Self {
            memo,
            store_nonce,
            generations,
            staged,
        })
    }

    /// Hydrate candidate rows that this batch selected together with their
    /// `blob_meta.publication_witness`, in selection order.
    ///
    /// Selection and hydration run on the same connection and transaction,
    /// with no write by the batch between them. `UNIQUE(blob_oid, lang,
    /// parse_variant)` holds within that snapshot, so the tuple lookup in
    /// `hydrate_candidate_rows` reads the same blob row, and so the same
    /// publication, that the candidate statement selected.
    pub(super) fn hydrate<T: CandidateRowContainer>(
        &mut self,
        conn: &Connection,
        rows: Vec<(T, Option<i64>)>,
    ) -> Result<Vec<T::Hydrated>> {
        let mut hydrated = Vec::with_capacity(rows.len());
        let mut misses = Vec::new();
        for (index, (row, witness)) in rows.into_iter().enumerate() {
            let candidate = row.candidate();
            let key = candidate_key(candidate);
            let witness = match witness {
                Some(witness) if witness > 0 => witness,
                other => {
                    return Err(StoreError::new(format!(
                        "analyzer store selected complete candidate {key:?} with publication witness {other:?}"
                    )));
                }
            };
            let generation = *self.generations.get(&candidate.lang).unwrap_or_else(|| {
                panic!(
                    "relational candidate language {} has no validated generation",
                    candidate.lang
                )
            });
            match self.reusable_segments(&key, generation, witness, &candidate.fq) {
                Some(segments) => {
                    let mut fq = candidate.fq.clone().map(RelationalUnitFq::from_header);
                    attach_complete_relational_fq(&mut fq, segments, &key)?;
                    hydrated.push(Some(row.with_hydrated_fq(fq)));
                    #[cfg(any(test, feature = "test-support"))]
                    self.memo.hits.fetch_add(1, Ordering::Relaxed);
                }
                None => {
                    hydrated.push(None);
                    misses.push(Miss {
                        index,
                        witness,
                        generation,
                        row,
                    });
                }
            }
        }
        if !misses.is_empty() {
            let loaded = hydrate_candidate_rows(conn, misses, None)?
                .expect("hydration without a cancellation token completes");
            for loaded in loaded {
                let entry = CandidateFqEntry {
                    store_nonce: self.store_nonce,
                    generation: loaded.generation,
                    witness: loaded.witness,
                    header: loaded.header,
                    segments: loaded.segments,
                };
                // A reread replaces the staged identity: the old one returns
                // its charge first, as in `finish`.
                let previous = self
                    .staged
                    .get(&loaded.key)
                    .map(|old| old.weight(&loaded.key));
                if let Some(old_bytes) = previous {
                    self.staged.remove_weighed(&loaded.key, old_bytes);
                }
                let bytes = entry.weight(&loaded.key);
                self.staged.insert_bounded_weighed(loaded.key, entry, bytes);
                #[cfg(any(test, feature = "test-support"))]
                {
                    if previous.is_none() {
                        self.memo.hydrated_keys.fetch_add(1, Ordering::Relaxed);
                    }
                    self.memo
                        .peak_staged_entries
                        .fetch_max(self.staged.len(), Ordering::Relaxed);
                    self.memo
                        .peak_staged_bytes
                        .fetch_max(self.staged.weighed_bytes(), Ordering::Relaxed);
                }
                hydrated[loaded.index] = Some(loaded.row);
            }
        }
        Ok(hydrated
            .into_iter()
            .map(|row| row.expect("every selected candidate is hydrated"))
            .collect())
    }

    fn reusable_segments(
        &self,
        key: &CandidateKey,
        generation: GenerationId,
        witness: i64,
        header: &Option<FqIdentityHeader>,
    ) -> Option<Vec<(SegmentKind, String)>> {
        if let Some(entry) = self.staged.get(key) {
            return entry
                .matches(&self.store_nonce, generation, witness, header)
                .then(|| entry.segments.clone());
        }
        let entries = self
            .memo
            .entries
            .lock()
            .expect("candidate FQ memo poisoned");
        entries
            .get(key)
            .filter(|entry| entry.matches(&self.store_nonce, generation, witness, header))
            .map(|entry| entry.segments.clone())
    }

    /// Admit the identities this batch read. Call only after the batch has
    /// completed without error or cancellation.
    pub(super) fn finish(self) {
        let mut entries = self
            .memo
            .entries
            .lock()
            .expect("candidate FQ memo poisoned");
        for (key, entry) in self.staged.into_entries() {
            // A newer identity for a held key replaces it under the caps: the
            // old entry returns its charge, and the new one is admitted or
            // refused like any other.
            if let Some(old_bytes) = entries.get(&key).map(|old| old.weight(&key)) {
                entries.remove_weighed(&key, old_bytes);
            }
            let bytes = entry.weight(&key);
            entries.insert_bounded_weighed(key, entry, bytes);
        }
    }
}
