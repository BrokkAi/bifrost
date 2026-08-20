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

use crate::analyzer::QueryScope;
use crate::analyzer::{IAnalyzer, Language, ProjectFile, Range};
use crate::cancellation::CancellationToken;
use crate::hash::HashSet;
use brokk_bifrost_core::analyzer::structural::rewrite_path::{
    RewriteDomainKind, RewriteOrigin, RewriteOutcome, RewritePath, RewriteTrace,
};
use brokk_bifrost_rust::graph_support::resolve_module_package_traced;

/// Why a file's rewrite-path derivation is not the complete answer.
///
/// Kept total and typed for the same reason every sibling family keeps one: a
/// consumer must be able to tell "this domain has no paths here" from "this
/// derivation could not run", and only the second may make a policy
/// unreliable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewritePathIncompleteReason {
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
            | RewritePathIncompleteReason::NoIndexedSource => true,
        })
    }

    fn from_reasons(reasons: Vec<RewritePathIncompleteReason>) -> Self {
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
    fn complete(paths: Vec<RewritePath>, generation: u64) -> Self {
        Self {
            paths,
            completeness: RewritePathCompleteness::Complete,
            generation,
        }
    }

    fn incomplete(reasons: Vec<RewritePathIncompleteReason>, generation: u64) -> Self {
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
/// Today exactly one domain is declared, so this runs the Rust import-alias
/// chase over the file's own import binders. A second domain becomes a second
/// branch here plus its own production chase; nothing in the row shape or the
/// query surface changes for it.
pub fn rewrite_paths_for_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    request: &mut RewritePathRequest<'_>,
) -> FileRewritePaths {
    let generation = analyzer.project().analysis_generation();
    if crate::analyzer::common::language_for_file(file) != Language::Rust {
        // The only declared domain does not apply here. That is an answer, not
        // a gap: there is nothing this derivation failed to compute.
        return FileRewritePaths::complete(Vec::new(), generation);
    }
    rust_import_alias_paths(analyzer, file, generation, request)
}

/// The `rust_import_alias` domain over one Rust file.
fn rust_import_alias_paths(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    generation: u64,
    request: &mut RewritePathRequest<'_>,
) -> FileRewritePaths {
    let domain = RewriteDomainKind::RustImportAlias;
    let scope = crate::analyzer::AnalyzerQueryScope::new(analyzer);
    let Some(rust) = crate::analyzer::resolve_analyzer::<crate::analyzer::RustAnalyzer>(analyzer)
    else {
        return FileRewritePaths::incomplete(
            vec![RewritePathIncompleteReason::NoDomainAnalyzer(domain)],
            generation,
        );
    };
    let Some(source) = analyzer.indexed_source(file) else {
        return FileRewritePaths::incomplete(
            vec![RewritePathIncompleteReason::NoIndexedSource],
            generation,
        );
    };
    let lines = LineIndex::build(&source);

    let mut reasons = Vec::new();
    let mut paths = Vec::new();
    let mut seen_origins: HashSet<String> = HashSet::default();
    for import in brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider::import_info_of(
        rust, file,
    ) {
        if request.cancellation.is_cancelled() {
            reasons.push(RewritePathIncompleteReason::Cancelled);
            break;
        }
        // A wildcard binds no single name, so it has no root the alias rule
        // can rewrite, and the binder records no rewritable root for it.
        if import.is_wildcard {
            continue;
        }
        let (Some(local_name), Some(span)) = (import.local_name(), import.binder_span) else {
            continue;
        };
        if !seen_origins.insert(local_name.to_string()) {
            continue;
        }
        let mut trace = RewriteTrace::default();
        // The production resolution, instrumented. Its answer is discarded
        // here on purpose: this layer reports how the chase terminated, and
        // the resolution result is the resolver's own business.
        let _resolved =
            resolve_module_package_traced(rust, scope.token(), file, local_name, Some(&mut trace))
                .is_some();
        let (declared_bound, steps, outcome) = trace.into_parts();
        // A specifier whose root no alias rewrites never engaged the domain,
        // so it is not a path through it.
        if steps.is_empty() {
            continue;
        }
        let outcome = outcome.unwrap_or(RewriteOutcome::ExceededBudget {
            explored: steps.len(),
        });
        paths.push(RewritePath {
            domain,
            origin: RewriteOrigin {
                file: file.clone(),
                specifier: local_name.to_string(),
                range: lines.range(span.start_byte, span.end_byte),
            },
            declared_bound,
            steps,
            outcome,
            generation,
        });
    }
    paths.sort_by_key(|path| {
        (
            path.origin.range.start_byte,
            path.origin.range.end_byte,
            path.origin.specifier.clone(),
        )
    });
    FileRewritePaths {
        paths,
        completeness: RewritePathCompleteness::from_reasons(reasons),
        generation,
    }
}

/// Byte offset to line number over one analyzed source.
///
/// Coordinate arithmetic over the exact bytes the analyzer indexed, not a
/// parse: the origin span comes from the adapter's own binder token, and this
/// only turns it into the line pair every row shape carries.
struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    fn build(source: &str) -> Self {
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
        match self.starts.binary_search(&offset) {
            Ok(line) => line + 1,
            Err(next) => next,
        }
    }

    fn range(&self, start_byte: usize, end_byte: usize) -> Range {
        Range {
            start_byte,
            end_byte,
            start_line: self.line_of(start_byte),
            end_line: self.line_of(end_byte),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_index_numbers_offsets_from_one() {
        let index = LineIndex::build("use a::b as c;\nuse c::d as a;\n");
        assert_eq!(index.line_of(0), 1);
        assert_eq!(index.line_of(13), 1);
        assert_eq!(index.line_of(15), 2);
        let range = index.range(15, 18);
        assert_eq!(range.start_line, 2);
        assert_eq!(range.end_line, 2);
        assert_eq!(range.start_byte, 15);
    }

    #[test]
    fn completeness_covers_a_domain_no_reason_blocks() {
        let complete = RewritePathCompleteness::Complete;
        assert!(complete.covers(RewriteDomainKind::RustImportAlias));
        assert!(complete.reasons().is_empty());
        let blocked = RewritePathCompleteness::from_reasons(vec![
            RewritePathIncompleteReason::NoDomainAnalyzer(RewriteDomainKind::RustImportAlias),
        ]);
        assert!(!blocked.covers(RewriteDomainKind::RustImportAlias));
        let cancelled =
            RewritePathCompleteness::from_reasons(vec![RewritePathIncompleteReason::Cancelled]);
        assert!(!cancelled.covers(RewriteDomainKind::RustImportAlias));
    }
}
