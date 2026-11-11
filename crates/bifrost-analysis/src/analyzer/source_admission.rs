//! Source-exact admission of files whose over-long lines are data, and of
//! files whose raw NUL bytes the grammar proves are payload.
//!
//! A line over the default limit is admitted when, after the maximal data
//! subtrees that intersect it (string, number and character literals and
//! composites of them, by the language's [`LineDataKinds`]) are excluded, its
//! remaining bytes fit the limit. Every language declares its tables, so the
//! rule holds for all of them. Only the excluded data has its own bound; the
//! rest of the tree gets exactly the limits an ordinary file gets. The NUL
//! proof applies to any NUL-bearing file whose language names its payload
//! node kinds, within a source-byte bound.
//!
//! [`LineDataKinds`]: brokk_bifrost_core::analyzer::tree_walk::LineDataKinds

use super::tree_sitter_analyzer::LanguageAdapter;
use crate::CancellationToken;
use brokk_bifrost_core::analyzer::tree_walk::maximal_data_subtrees;
use std::ops::ControlFlow;
use std::time::Instant;
use tree_sitter::Tree;

const MAX_SOURCE_BYTES: usize = 1024 * 1024;
const MAX_EXCLUDED_NODES: usize = 8192;
const LINE_LIMIT: usize = brokk_bifrost_core::analyzer::common::DEFAULT_MAX_LINE_LENGTH;

/// Version covers the bounds as well as the shared accounting rule. Version 2
/// (#10694) admits data lines in every language and bounds only the excluded
/// data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct SourceAdmissionPolicy {
    version: u8,
    explicit_line_limit: Option<usize>,
}

impl SourceAdmissionPolicy {
    #[doc(hidden)]
    pub fn current() -> Self {
        Self::from_setting(std::env::var("BIFROST_MAX_LINE_LENGTH").ok().as_deref())
    }

    #[doc(hidden)]
    pub fn from_setting(setting: Option<&str>) -> Self {
        Self {
            version: 2,
            explicit_line_limit: setting.and_then(|value| value.trim().parse().ok()),
        }
    }

    /// Stable scalar identity of the effective rule, including its bounds.
    /// Default and explicit16000 differ even though their raw line caps match.
    pub(crate) fn hash_identity(&self, hasher: &mut super::canonical_hash::CanonicalHasher) {
        hasher.field("policy_version", &[self.version]);
        match self.explicit_line_limit {
            None => hasher.field("line_policy", &[0]),
            Some(limit) => {
                hasher.field("line_policy", &[1]);
                hasher.field(
                    "explicit_line_limit",
                    &u64::try_from(limit)
                        .expect("supported usize fits u64")
                        .to_be_bytes(),
                );
            }
        }
        let parse_budget = super::tree_sitter_analyzer::COMPLETE_FILE_PARSE_BUDGET;
        hasher.field(
            "parse_budget_seconds",
            &parse_budget.as_secs().to_be_bytes(),
        );
        hasher.field(
            "parse_budget_subsec_nanos",
            &parse_budget.subsec_nanos().to_be_bytes(),
        );
        for (name, limit) in [
            ("default_structural_line_bytes", LINE_LIMIT),
            ("nul_payload_source_bytes", MAX_SOURCE_BYTES),
            ("excluded_all_ast_nodes", MAX_EXCLUDED_NODES),
        ] {
            hasher.field(
                name,
                &u64::try_from(limit)
                    .expect("supported usize fits u64")
                    .to_be_bytes(),
            );
        }
    }

    /// The AST proofs the source needs; an empty answer needs none. Needing a
    /// proof is not admission: [`validate_tree`] decides that on the tree.
    pub(crate) fn requires_proof<A: LanguageAdapter + ?Sized>(
        self,
        adapter: &A,
        source: &str,
    ) -> Result<RequiredProof, SourceAdmissionRefusal> {
        let nul_payloads = source.as_bytes().contains(&0);
        if nul_payloads {
            if adapter.nul_payload_kinds().is_empty() {
                return Err(SourceAdmissionRefusal::Binary);
            }
            check_limit(
                AdmissionDimension::SourceBytes,
                source.len(),
                MAX_SOURCE_BYTES,
            )?;
        }
        let proof = RequiredProof {
            nul_payloads,
            structural_lines: false,
        };
        let limit = match self.explicit_line_limit {
            Some(0) => return Ok(proof),
            Some(limit) => limit,
            None => LINE_LIMIT,
        };
        let longest = source.lines().map(str::len).max().unwrap_or(0);
        if longest <= limit {
            return Ok(proof);
        }
        if self.explicit_line_limit.is_some() {
            return Err(SourceAdmissionRefusal::StructuralLine {
                limit,
                observed: longest,
            });
        }
        Ok(RequiredProof {
            structural_lines: true,
            ..proof
        })
    }
}

/// Which AST proofs [`validate_tree`] must establish before admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RequiredProof {
    nul_payloads: bool,
    structural_lines: bool,
}

impl RequiredProof {
    pub(crate) const fn any(self) -> bool {
        self.nul_payloads || self.structural_lines
    }
}

pub use crate::analyzer::semantic::source_admission::AdmissionDimension;

pub use crate::analyzer::semantic::source_admission::SourceAdmissionRefusal;

fn check_limit(
    dimension: AdmissionDimension,
    observed: usize,
    limit: usize,
) -> Result<(), SourceAdmissionRefusal> {
    if observed > limit {
        Err(SourceAdmissionRefusal::Budget {
            dimension,
            limit,
            observed,
        })
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum AdmissionStop {
    Refused(SourceAdmissionRefusal),
    Cancelled,
    TimedOut,
}

impl From<SourceAdmissionRefusal> for AdmissionStop {
    fn from(reason: SourceAdmissionRefusal) -> Self {
        Self::Refused(reason)
    }
}

fn stopped(
    cancellation: Option<&CancellationToken>,
    deadline: Instant,
) -> Result<(), AdmissionStop> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        Err(AdmissionStop::Cancelled)
    } else if Instant::now() >= deadline {
        Err(AdmissionStop::TimedOut)
    } else {
        Ok(())
    }
}

/// Validate every actual tree before a language hook or extraction sees it.
pub(crate) fn validate_tree<A: LanguageAdapter + ?Sized>(
    proof: RequiredProof,
    adapter: &A,
    source: &str,
    tree: &Tree,
    cancellation: Option<&CancellationToken>,
    deadline: Instant,
) -> Result<(), AdmissionStop> {
    if proof.nul_payloads {
        validate_nul_payloads(adapter, source, tree, cancellation, deadline)?;
    }
    if proof.structural_lines {
        validate_lines(adapter, source, tree, cancellation, deadline)?;
    }
    Ok(())
}

/// Every raw NUL must lie in grammar-owned payload: the smallest node covering
/// the byte has one of the language's payload kinds, and neither it nor an
/// ancestor is an error or missing node. A NUL anywhere else, including one
/// the parser recovered around, leaves the file refused as binary, so a real
/// binary is never admitted and the admitted text keeps its exact bytes.
fn validate_nul_payloads<A: LanguageAdapter + ?Sized>(
    adapter: &A,
    source: &str,
    tree: &Tree,
    cancellation: Option<&CancellationToken>,
    deadline: Instant,
) -> Result<(), AdmissionStop> {
    let root = tree.root_node();
    let payload_kinds = adapter.nul_payload_kinds();
    for (offset, _) in source.match_indices('\0') {
        stopped(cancellation, deadline)?;
        let node = root
            .descendant_for_byte_range(offset, offset + 1)
            .expect("a NUL byte inside the source lies under the root");
        if !payload_kinds.contains(&node.kind()) {
            return Err(SourceAdmissionRefusal::Binary.into());
        }
        // An error-free tree has no error or missing ancestor to find.
        if root.has_error() {
            let mut current = Some(node);
            while let Some(ancestor) = current {
                if ancestor.is_error() || ancestor.is_missing() {
                    return Err(SourceAdmissionRefusal::Binary.into());
                }
                current = ancestor.parent();
            }
        }
    }
    Ok(())
}

fn validate_lines<A: LanguageAdapter + ?Sized>(
    adapter: &A,
    source: &str,
    tree: &Tree,
    cancellation: Option<&CancellationToken>,
    deadline: Instant,
) -> Result<(), AdmissionStop> {
    let mut offset = 0;
    let mut overlong_lines = Vec::new();
    for line in source.split_inclusive('\n') {
        let text = line.strip_suffix('\n').unwrap_or(line);
        let text = if line.ends_with('\n') {
            text.strip_suffix('\r').unwrap_or(text)
        } else {
            text
        };
        if text.len() > LINE_LIMIT {
            overlong_lines.push(offset..offset + text.len());
        }
        offset += line.len();
    }
    let mut should_stop =
        || cancellation.is_some_and(CancellationToken::is_cancelled) || Instant::now() >= deadline;
    let intersects_overlong = |node: tree_sitter::Node<'_>| {
        let first_line = overlong_lines.partition_point(|line| line.end <= node.start_byte());
        overlong_lines
            .get(first_line)
            .is_some_and(|line| line.start < node.end_byte())
    };
    let subtrees = match maximal_data_subtrees(
        tree.root_node(),
        &adapter.line_data_kinds(),
        intersects_overlong,
        &mut should_stop,
    ) {
        ControlFlow::Continue(subtrees) => subtrees,
        ControlFlow::Break(()) => {
            stopped(cancellation, deadline)?;
            unreachable!("data discovery stops only on cancellation or the deadline")
        }
    };
    check_limit(
        AdmissionDimension::ExcludedNodes,
        subtrees.iter().map(|subtree| subtree.nodes).sum(),
        MAX_EXCLUDED_NODES,
    )?;
    // The subtrees are in source order, maximal and disjoint.
    let mut offset = 0usize;
    let mut first_range = 0usize;
    for line in source.split_inclusive('\n') {
        stopped(cancellation, deadline)?;
        // Match str::lines: omit LF and an optional preceding CR.
        let text = line.strip_suffix('\n').unwrap_or(line);
        let text = if line.ends_with('\n') {
            text.strip_suffix('\r').unwrap_or(text)
        } else {
            text
        };
        let end = offset + text.len();
        while first_range < subtrees.len() && subtrees[first_range].range.end <= offset {
            first_range += 1;
        }
        let mut excluded = 0usize;
        for subtree in &subtrees[first_range..] {
            if subtree.range.start >= end {
                break;
            }
            excluded += subtree
                .range
                .end
                .min(end)
                .saturating_sub(subtree.range.start.max(offset));
        }
        let structural = text.len() - excluded;
        if structural > LINE_LIMIT {
            return Err(SourceAdmissionRefusal::StructuralLine {
                limit: LINE_LIMIT,
                observed: structural,
            }
            .into());
        }
        offset += line.len();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::Language;
    use crate::analyzer::store::StoreLanguageAdapter;
    use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;

    struct PythonAdapter;
    impl StoreLanguageAdapter for PythonAdapter {
        // Test adapter.
        fn parse_time_semantic_lowerer(
            &self,
        ) -> Option<brokk_bifrost_analysis::analyzer::semantic::service::ParseTimeSemanticLowerer>
        {
            None
        }
        fn language(&self) -> Language {
            Language::Python
        }
    }
    impl LanguageAdapter for PythonAdapter {
        fn query_directory(&self) -> &'static str {
            "python"
        }
        fn line_data_kinds(&self) -> brokk_bifrost_core::analyzer::tree_walk::LineDataKinds {
            brokk_bifrost_core::analyzer::tree_walk::LineDataKinds {
                literals: &["integer"],
                interpolations: &[],
                composites: &[("tuple", &["(", ")", ","])],
            }
        }
        fn file_extension(&self) -> &'static str {
            "py"
        }
        fn extract_call_receiver(&self, _reference: &str) -> Option<String> {
            None
        }
        fn parse_file(
            &self,
            _file: &crate::analyzer::ProjectFile,
            _source: &str,
            _tree: &tree_sitter::Tree,
        ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
            unimplemented!()
        }
    }

    #[test]
    fn a_line_at_the_inclusive_limit_does_not_enter_structural_exclusion() {
        let mut source = format!("({})", "1,".repeat(7_000));
        source.push_str(&" ".repeat(LINE_LIMIT - source.len()));
        assert_eq!(source.len(), LINE_LIMIT);
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(&source, None).unwrap();
        assert!(
            validate_lines(
                &PythonAdapter,
                &source,
                &tree,
                None,
                Instant::now() + std::time::Duration::from_secs(30)
            )
            .is_ok()
        );
    }
}
