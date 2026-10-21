//! Static package file facts shared by dependency discovery (#2442).
//!
//! These are acquisition values, not a second inventory or activation route.
//! A caller may hold one bounded acquisition result; durable readers must use
//! the selected workspace store. Versions retain ecosystem syntax, never a
//! lossy conversion to the semantic pack catalog's semver coordinates.

use std::ops::Range;
use std::path::PathBuf;

use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;

use brokk_bifrost_core::analyzer::canonical_hash::lower_hex_string;

use crate::analyzer::semantic::topology::DependencyScope;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyEvidenceKind {
    Declared,
    Constraint,
    Locked,
    Installed,
    /// A checksum proves recorded bytes, not dependency selection.
    Checksum,
}

impl DependencyEvidenceKind {
    pub const ALL: [Self; 5] = [
        Self::Declared,
        Self::Constraint,
        Self::Locked,
        Self::Installed,
        Self::Checksum,
    ];
    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.label() == label)
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Constraint => "constraint",
            Self::Locked => "locked",
            Self::Installed => "installed",
            Self::Checksum => "checksum",
        }
    }
}

/// Ecosystem conditions are retained without assuming host configuration.
/// Examples include marker, requested_extra, extra, group, target and feature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyCondition {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyEvidence {
    pub ecosystem: String,
    pub package: String,
    pub kind: DependencyEvidenceKind,
    pub version_requirement: Option<String>,
    pub exact_version: Option<String>,
    pub source: Option<String>,
    /// Adapter-specific instance location; never an import-module identity.
    pub locator: Option<String>,
    pub declared_by: Option<String>,
    pub scope: DependencyScope,
    pub conditions: Vec<DependencyCondition>,
    pub build_file: PathBuf,
    /// Content identity of the exact snapshot parsed, independent of stat.
    pub source_digest: String,
    pub byte_range: Range<usize>,
    /// Completeness of this record's supported interpretation, not selection.
    pub complete: bool,
}

impl DependencyEvidence {
    pub fn id(&self) -> String {
        let mut h = CanonicalHasher::new(b"bifrost.dependency-evidence.v1");
        for (key, value) in [
            ("ecosystem", self.ecosystem.as_str()),
            ("package", self.package.as_str()),
            ("kind", self.kind.label()),
            (
                "requirement",
                self.version_requirement.as_deref().unwrap_or(""),
            ),
            ("version", self.exact_version.as_deref().unwrap_or("")),
            ("source", self.source.as_deref().unwrap_or("")),
            ("locator", self.locator.as_deref().unwrap_or("")),
            ("owner", self.declared_by.as_deref().unwrap_or("")),
            ("scope", self.scope.label()),
            ("snapshot", self.source_digest.as_str()),
        ] {
            h.field(key, value.as_bytes());
        }
        h.field(
            "file",
            self.build_file
                .to_string_lossy()
                .replace('\\', "/")
                .as_bytes(),
        );
        h.field("start", &(self.byte_range.start as u64).to_le_bytes());
        h.field("end", &(self.byte_range.end as u64).to_le_bytes());
        h.field("complete", &[u8::from(self.complete)]);
        h.sequence("conditions", &self.conditions, |h, condition| {
            h.field("kind", condition.kind.as_bytes());
            h.field("value", condition.value.as_bytes());
        });
        lower_hex_string(&h.finish())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyEvidenceGapKind {
    Malformed,
    Unsupported,
    Unresolved,
    Conflict,
    UnsafePath,
    Cycle,
    Missing,
    Limit,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyEvidenceGap {
    pub kind: DependencyEvidenceGapKind,
    pub build_file: PathBuf,
    pub byte_range: Range<usize>,
    pub message: String,
}

/// Request/acquisition-scoped only. A gap prevents a complete absence claim.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DependencyFileEvidence {
    pub rows: Vec<DependencyEvidence>,
    pub gaps: Vec<DependencyEvidenceGap>,
    pub files_read: usize,
    pub bytes_read: usize,
}

impl DependencyFileEvidence {
    pub fn complete(&self) -> bool {
        self.gaps.is_empty() && self.rows.iter().all(|row| row.complete)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DependencyFileEvidenceLimits {
    pub max_files: usize,
    pub max_file_bytes: usize,
    pub max_total_bytes: usize,
    pub max_rows: usize,
    pub max_include_depth: usize,
}

impl Default for DependencyFileEvidenceLimits {
    fn default() -> Self {
        Self {
            max_files: 256,
            max_file_bytes: 4 * 1024 * 1024,
            max_total_bytes: 16 * 1024 * 1024,
            max_rows: 50_000,
            max_include_depth: 32,
        }
    }
}

/// Presentation proof derived from retained input bytes. It is deliberately
/// separate from package identity and the shared acquisition contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DependencyEvidenceLocation {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub slice_sha256: [u8; 32],
}
