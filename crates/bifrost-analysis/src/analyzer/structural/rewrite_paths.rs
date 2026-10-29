//! The bounded rewrite-path derivation layer (issue #1480, milestone 4).
//!
//! One *rewrite path* is one bounded chase through a declared finite rewrite
//! domain: the ordered steps a production analysis took, the bound the domain
//! declared for itself, and how the chase terminated.
//!
//! The first domain is the Rust import-alias chase in
//! `brokk_bifrost_rust::graph_support::resolve_module_package`, whose fix
//! (mined commit `9deded6f5`) is the contract: the semantic state key is the
//! specifier's root, because the rewrite replaces only the root and the
//! specifier grows every hop; the bound is the importing file's binder root
//! count; and the terminal outcome is converged, cycle, or exceeded-budget.
//!
//! The instrumented chase *is* the production chase. This module attaches a
//! [`RewriteTrace`] to
//! [`resolve_module_package_traced`](brokk_bifrost_rust::graph_support::resolve_module_package_traced),
//! which `resolve_module_package` itself calls with no collector; there is no
//! second walk of the binder here, and nothing in this module re-implements a
//! resolution rule.
//!
//! A file the domain does not apply to -- a file that is not Rust, or a Rust
//! file no import of which engages the alias rule -- yields an empty *complete*
//! result. Incompleteness is reserved for what the derivation genuinely could
//! not answer: a cancelled run, a missing Rust analyzer, a file whose source
//! the analyzer no longer holds.

use crate::analyzer::AnalyzerQueryScope;
use crate::analyzer::QueryScope;
use crate::analyzer::{IAnalyzer, ProjectFile, Range};
use crate::cancellation::CancellationToken;
use crate::text_utils::find_line_index_for_offset;
use brokk_bifrost_core::analyzer::structural::rewrite_path::{RewriteDomainKind, RewritePath};

/// Why a file's rewrite-path derivation is not the complete answer.
///
/// Kept total and typed for the same reason every sibling family keeps one: a
/// consumer must be able to tell "this domain has no paths here" from "this
/// derivation could not run", and only the second may make a policy
/// unreliable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewritePathIncompleteReason {
    CanonicalFactsUnavailable,
    /// The workspace has no Rust analyzer, so a Rust file's alias chase cannot
    /// be run at all.
    NoDomainAnalyzer(RewriteDomainKind),
    /// The run was cancelled part way through the file's imports.
    Cancelled,
    /// The analyzer no longer holds the analyzed source of the file, so the
    /// origin sites cannot be anchored.
    NoIndexedSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewritePathCompleteness {
    Complete,
    Incomplete {
        reasons: Vec<RewritePathIncompleteReason>,
    },
}

impl RewritePathCompleteness {
    pub fn reasons(&self) -> &[RewritePathIncompleteReason] {
        match self {
            Self::Complete => &[],
            Self::Incomplete { reasons } => reasons,
        }
    }

    /// Whether the rows for `domain` can be trusted to be the complete set.
    /// The domain is the only axis this family has: a path row belongs to
    /// exactly one domain, and a hole in one domain says nothing about
    /// another.
    pub fn covers(&self, domain: RewriteDomainKind) -> bool {
        !self.reasons().iter().any(|reason| match reason {
            RewritePathIncompleteReason::NoDomainAnalyzer(blocked) => *blocked == domain,
            RewritePathIncompleteReason::Cancelled
            | RewritePathIncompleteReason::CanonicalFactsUnavailable
            | RewritePathIncompleteReason::NoIndexedSource => true,
        })
    }

    #[doc(hidden)]
    pub fn from_reasons(reasons: Vec<RewritePathIncompleteReason>) -> Self {
        if reasons.is_empty() {
            Self::Complete
        } else {
            Self::Incomplete { reasons }
        }
    }
}

/// Every bounded chase one file engages, with the account of what is missing.
#[derive(Debug, Clone)]
pub struct FileRewritePaths {
    pub paths: Vec<RewritePath>,
    pub completeness: RewritePathCompleteness,
    pub generation: u64,
}

impl FileRewritePaths {
    pub(crate) fn complete(paths: Vec<RewritePath>, generation: u64) -> Self {
        Self {
            paths,
            completeness: RewritePathCompleteness::Complete,
            generation,
        }
    }

    #[doc(hidden)]
    pub fn incomplete(reasons: Vec<RewritePathIncompleteReason>, generation: u64) -> Self {
        Self {
            paths: Vec::new(),
            completeness: RewritePathCompleteness::Incomplete { reasons },
            generation,
        }
    }
}

/// Borrowed controls for one derivation.
#[derive(Debug)]
pub struct RewritePathRequest<'request> {
    pub cancellation: &'request CancellationToken,
}

impl<'request> RewritePathRequest<'request> {
    pub fn new(cancellation: &'request CancellationToken) -> Self {
        Self { cancellation }
    }
}

/// Derive every bounded rewrite path one file engages.
///
/// The language support derives its declared domains using their production
/// chases. Languages with no declared domain return an empty complete result.
pub fn rewrite_paths_for_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    request: &mut RewritePathRequest<'_>,
) -> FileRewritePaths {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let generation = analyzer.project().analysis_generation();
    let language = crate::analyzer::common::language_for_file(file);
    match crate::analyzer::languages::language_support_for_hook(language, "rewrite_paths") {
        Some(support) => support.rewrite_paths(analyzer, token, file, generation, request),
        None => FileRewritePaths::complete(Vec::new(), generation),
    }
}

/// Derive one file's rewrite paths with the default request controls.
pub fn rewrite_paths_for_file_with_cancellation(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    cancellation: Option<&CancellationToken>,
) -> FileRewritePaths {
    let token = cancellation.cloned().unwrap_or_default();
    rewrite_paths_for_file(analyzer, file, &mut RewritePathRequest::new(&token))
}

/// Byte offset to line number over one analyzed source.
///
/// Coordinate arithmetic over the exact bytes the analyzer indexed, not a
/// parse: the origin span comes from the adapter's own binder token, and this
/// only turns it into the line pair every row shape carries.
#[doc(hidden)]
pub struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    #[doc(hidden)]
    pub fn build(source: &str) -> Self {
        let mut starts = vec![0usize];
        starts.extend(
            source
                .bytes()
                .enumerate()
                .filter(|(_, byte)| *byte == b'\n')
                .map(|(offset, _)| offset + 1),
        );
        Self { starts }
    }

    fn line_of(&self, offset: usize) -> usize {
        find_line_index_for_offset(&self.starts, offset) + 1
    }

    #[doc(hidden)]
    pub fn range(&self, start_byte: usize, end_byte: usize) -> Range {
        Range {
            start_byte,
            end_byte,
            start_line: self.line_of(start_byte),
            end_line: self.line_of(end_byte),
        }
    }
}

#[test]
fn line_ranges_preserve_byte_coordinates_across_newlines() {
    for source in ["", "a\nb\n", "caf\u{e9}\r\n\u{3b2}\nlast", "a\r\nb"] {
        let index = LineIndex::build(source);
        for start in 0..=source.len() {
            for end in start..=source.len() {
                let range = index.range(start, end);
                let line = |offset| {
                    source.as_bytes()[..offset]
                        .iter()
                        .filter(|&&byte| byte == b'\n')
                        .count()
                        + 1
                };
                assert_eq!((range.start_byte, range.end_byte), (start, end));
                assert_eq!((range.start_line, range.end_line), (line(start), line(end)));
            }
        }
    }
}

#[test]
fn completeness_covers_a_domain_no_reason_blocks() {
    let complete = RewritePathCompleteness::Complete;
    assert!(complete.covers(RewriteDomainKind::RustImportAlias));
    assert!(complete.reasons().is_empty());
    let blocked =
        RewritePathCompleteness::from_reasons(vec![RewritePathIncompleteReason::NoDomainAnalyzer(
            RewriteDomainKind::RustImportAlias,
        )]);
    assert!(!blocked.covers(RewriteDomainKind::RustImportAlias));
    let cancelled =
        RewritePathCompleteness::from_reasons(vec![RewritePathIncompleteReason::Cancelled]);
    assert!(!cancelled.covers(RewriteDomainKind::RustImportAlias));
}

#[test]
fn rewrite_completeness_preserves_every_supplied_cause() {
    let causes = [
        RewritePathIncompleteReason::Cancelled,
        RewritePathIncompleteReason::NoIndexedSource,
        RewritePathIncompleteReason::NoDomainAnalyzer(RewriteDomainKind::RustImportAlias),
    ];
    for mask in 0..8 {
        let reasons: Vec<_> = causes
            .iter()
            .enumerate()
            .filter(|(id, _)| mask & (1 << id) != 0)
            .map(|(_, cause)| cause.clone())
            .collect();
        for rotation in 0..reasons.len().max(1) {
            let mut ordered = reasons.clone();
            if !ordered.is_empty() {
                ordered.rotate_left(rotation);
            }
            let completeness = RewritePathCompleteness::from_reasons(ordered.clone());
            assert_eq!(completeness.reasons(), ordered);
            assert_eq!(
                completeness.covers(RewriteDomainKind::RustImportAlias),
                reasons.is_empty()
            );
        }
    }
}

#[test]
fn files_without_rewrite_domains_are_complete_without_sources() {
    let temp = tempfile::tempdir().unwrap();
    let analyzer = super::identity_routes::tests::MetadataAnalyzer::new(temp.path());
    let _hooks = crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[
        crate::analyzer::Language::Java,
    ]);
    for path in ["unknown.unregistered_extension", "Example.java"] {
        let file = ProjectFile::new(temp.path(), path);
        let token = CancellationToken::default();
        let answer = rewrite_paths_for_file(&analyzer, &file, &mut RewritePathRequest::new(&token));
        assert!(answer.paths.is_empty());
        assert_eq!(answer.completeness, RewritePathCompleteness::Complete);
    }
}
