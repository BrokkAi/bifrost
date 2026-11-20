//! Immutable store failure vocabulary shared by analyzer lookup contracts.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreErrorKind {
    Generic,
    /// This build observed no workspace listing and cannot select a current head.
    WorkspaceListingUnavailable,
    /// A requested source language was deliberately omitted from this build.
    WorkspaceLanguageNotSelected,
    NotWritable,
    StaleGeneration,
    StaleResolution,
    SqliteInterrupted,
    Cancelled,
    ResourceBound,
    Corrupt,
    /// The stored read vocabulary is newer than this reader understands.
    UnsupportedReadKey,
    /// The store is construction material and cannot publish yet.
    UnmintedPublication,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError {
    message: String,
    #[doc(hidden)]
    pub kind: StoreErrorKind,
    #[doc(hidden)]
    pub missing_required_source_facts: bool,
}

impl crate::retention_budget::RetainedBytes for StoreError {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + crate::allocation_size::allocation_size(self.message.capacity())
    }
}

impl StoreError {
    /// Owned message allocation, excluding the inline error value.
    #[doc(hidden)]
    pub fn retained_message_capacity(&self) -> usize {
        self.message.capacity()
    }

    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: StoreErrorKind::Generic,
            missing_required_source_facts: false,
        }
    }

    #[doc(hidden)]
    pub fn workspace_listing_unavailable(cause: &str) -> Self {
        Self {
            message: format!(
                "workspace listing unavailable: {cause}; fix the listing cause and update or rebuild the workspace"
            ),
            kind: StoreErrorKind::WorkspaceListingUnavailable,
            missing_required_source_facts: false,
        }
    }

    #[doc(hidden)]
    pub fn workspace_languages_not_selected(
        languages: &std::collections::BTreeSet<crate::analyzer::Language>,
    ) -> Self {
        Self {
            message: format!(
                "workspace languages not selected: {languages:?}; rebuild the workspace with these languages selected"
            ),
            kind: StoreErrorKind::WorkspaceLanguageNotSelected,
            missing_required_source_facts: false,
        }
    }

    #[doc(hidden)]
    pub fn missing_required_source_facts(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: StoreErrorKind::Generic,
            missing_required_source_facts: true,
        }
    }

    #[doc(hidden)]
    pub fn is_missing_required_source_facts(&self) -> bool {
        self.missing_required_source_facts
    }

    #[doc(hidden)]
    pub fn cancelled(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: StoreErrorKind::Cancelled,
            missing_required_source_facts: false,
        }
    }

    #[doc(hidden)]
    pub fn stale_generation(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: StoreErrorKind::StaleGeneration,
            missing_required_source_facts: false,
        }
    }

    #[doc(hidden)]
    pub fn stale_resolution(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: StoreErrorKind::StaleResolution,
            missing_required_source_facts: false,
        }
    }

    #[doc(hidden)]
    pub fn resource_bound(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: StoreErrorKind::ResourceBound,
            missing_required_source_facts: false,
        }
    }

    #[doc(hidden)]
    pub fn corrupt(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: StoreErrorKind::Corrupt,
            missing_required_source_facts: false,
        }
    }

    #[doc(hidden)]
    pub fn unsupported_read_key(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: StoreErrorKind::UnsupportedReadKey,
            missing_required_source_facts: false,
        }
    }

    pub fn is_unsupported_read_key(&self) -> bool {
        self.kind == StoreErrorKind::UnsupportedReadKey
    }

    pub fn kind(&self) -> StoreErrorKind {
        self.kind
    }

    pub fn is_stale_generation(&self) -> bool {
        self.kind == StoreErrorKind::StaleGeneration
    }

    pub fn is_resource_bound(&self) -> bool {
        self.kind == StoreErrorKind::ResourceBound
    }

    pub fn is_corrupt(&self) -> bool {
        self.kind == StoreErrorKind::Corrupt
    }

    #[doc(hidden)]
    pub fn is_stale_resolution(&self) -> bool {
        self.kind == StoreErrorKind::StaleResolution
    }

    #[doc(hidden)]
    pub fn is_cancelled(&self) -> bool {
        self.kind == StoreErrorKind::Cancelled
    }

    #[doc(hidden)]
    pub fn is_sqlite_interrupted(&self) -> bool {
        self.kind == StoreErrorKind::SqliteInterrupted
    }

    #[doc(hidden)]
    pub fn context(self, context: impl fmt::Display) -> Self {
        Self {
            message: format!("{context}: {}", self.message),
            kind: self.kind,
            missing_required_source_facts: self.missing_required_source_facts,
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(err: std::io::Error) -> Self {
        Self::new(format!("analyzer store I/O error: {err}"))
    }
}

impl From<crate::cache_db::publication_lineage::PublicationLineageError> for StoreError {
    fn from(error: crate::cache_db::publication_lineage::PublicationLineageError) -> Self {
        use crate::cache_db::publication_lineage::PublicationLineageError;
        match error {
            PublicationLineageError::Unminted => Self {
                message: "store publication lineage is not minted".to_owned(),
                kind: StoreErrorKind::UnmintedPublication,
                missing_required_source_facts: false,
            },
            PublicationLineageError::Sqlite(error) => error.into(),
            error => Self::corrupt(error.to_string()),
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(err: rusqlite::Error) -> Self {
        let code = err.sqlite_error_code();
        let message = if let Some(sqlite) = err.sqlite_error() {
            format!(
                "analyzer store SQLite error: {err} (code: {:?}, extended code: {})",
                sqlite.code, sqlite.extended_code
            )
        } else {
            format!("analyzer store SQLite error: {err}")
        };
        Self {
            message,
            kind: if code == Some(rusqlite::ErrorCode::OperationInterrupted) {
                StoreErrorKind::SqliteInterrupted
            } else if matches!(
                code,
                Some(rusqlite::ErrorCode::ReadOnly | rusqlite::ErrorCode::DiskFull)
            ) {
                StoreErrorKind::NotWritable
            } else if matches!(
                err,
                rusqlite::Error::InvalidColumnType(..)
                    | rusqlite::Error::IntegralValueOutOfRange(..)
            ) || matches!(
                code,
                Some(rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase)
            ) {
                StoreErrorKind::Corrupt
            } else {
                StoreErrorKind::Generic
            },
            missing_required_source_facts: false,
        }
    }
}

impl From<git2::Error> for StoreError {
    fn from(err: git2::Error) -> Self {
        Self::new(format!("analyzer store git error: {err}"))
    }
}
