//! Scalar publication authority. NULL is construction state, never a receipt.
use rusqlite::{Connection, OptionalExtension, Transaction};

/// Failure to obtain publication authority from an existing store.
#[derive(Debug)]
pub enum PublicationLineageError {
    Unminted,
    Missing,
    InvalidNonceLength(usize),
    Sqlite(rusqlite::Error),
}

impl std::fmt::Display for PublicationLineageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unminted => f.write_str("store publication lineage is not minted"),
            Self::Missing => f.write_str("store publication lineage is missing"),
            Self::InvalidNonceLength(len) => {
                write!(f, "store publication nonce has {len} bytes, expected 16")
            }
            Self::Sqlite(error) => write!(f, "store publication lineage SQLite error: {error}"),
        }
    }
}
impl std::error::Error for PublicationLineageError {}

/// Require a minted nonce in the caller's current transaction, before effects.
///
/// Import construction authority cannot be obtained by external store callers:
/// ```compile_fail
/// use brokk_bifrost_core::cache_db::staged_import::StagedImport;
/// ```
/// Nor is the NULL-only constructor mint an opened-store operation:
/// ```compile_fail
/// use brokk_bifrost_core::cache_db::publication_lineage::mint_publication_nonce;
/// ```
pub fn require_publication_nonce(conn: &Connection) -> Result<[u8; 16], PublicationLineageError> {
    let nonce: Option<Option<Vec<u8>>> = conn
        .prepare_cached("SELECT store_nonce FROM blob_publication_witness_sequence WHERE id = 1")
        .and_then(|mut statement| statement.query_row([], |row| row.get(0)).optional())
        .map_err(PublicationLineageError::Sqlite)?;
    let nonce = nonce
        .ok_or(PublicationLineageError::Missing)?
        .ok_or(PublicationLineageError::Unminted)?;
    nonce
        .as_slice()
        .try_into()
        .map_err(|_| PublicationLineageError::InvalidNonceLength(nonce.len()))
}

/// Construction only: no counter movement, transaction control or reset path.
pub(super) fn mint_publication_nonce(tx: &Transaction<'_>) -> super::Result<[u8; 16]> {
    let nonce: Vec<u8> = tx
        .query_row(
            "UPDATE blob_publication_witness_sequence SET store_nonce = randomblob(16)
         WHERE id = 1 AND store_nonce IS NULL RETURNING store_nonce",
            [],
            |row| row.get(0),
        )
        .map_err(|error| format!("store publication lineage mint failed: {error}"))?;
    nonce.as_slice().try_into().map_err(|_| {
        format!(
            "minted publication nonce has {} bytes, expected 16",
            nonce.len()
        )
    })
}
