//! Bounded, source-exact admission of structurally small files with bulk data,
//! and of files whose raw NUL bytes the grammar proves are payload.
//!
//! The structural-line bounds apply only to a default-overlong file whose
//! language opts in. They are not an allocator reservation or a bound on all
//! language extraction. The NUL proof applies to any NUL-bearing file whose
//! language names its payload node kinds, within the same source-byte bound.

use super::tree_sitter_analyzer::LanguageAdapter;
use crate::CancellationToken;
use std::ops::ControlFlow;
use std::time::Instant;
use tree_sitter::Tree;

const MAX_SOURCE_BYTES: usize = 1024 * 1024;
const MAX_NODES: usize = 65_536;
const MAX_DEPTH: usize = 128;
const MAX_SPAN_BYTES: usize = 8 * 1024 * 1024;
const MAX_EXCLUDED_NODES: usize = 8192;
const LINE_LIMIT: usize = brokk_bifrost_core::analyzer::common::DEFAULT_MAX_LINE_LENGTH;

/// Version covers the finite envelope as well as the shared accounting rule.
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
            version: 1,
            explicit_line_limit: setting.and_then(|value| value.trim().parse().ok()),
        }
    }

    /// Stable scalar identity of the effective rule, including its finite envelope.
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
            ("source_bytes", MAX_SOURCE_BYTES),
            ("all_ast_nodes", MAX_NODES),
            ("ast_depth", MAX_DEPTH),
            ("ast_span_bytes", MAX_SPAN_BYTES),
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
        if self.explicit_line_limit.is_some() || !adapter.supports_structural_line_data() {
            return Err(SourceAdmissionRefusal::StructuralLine {
                limit,
                observed: longest,
            });
        }
        check_limit(
            AdmissionDimension::SourceBytes,
            source.len(),
            MAX_SOURCE_BYTES,
        )?;
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
        validate_structural_envelope(adapter, source, tree, cancellation, deadline)?;
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

/// Cursor traversal retains no sibling frontier and counts anonymous nodes too.
fn validate_structural_envelope<A: LanguageAdapter + ?Sized>(
    adapter: &A,
    source: &str,
    tree: &Tree,
    cancellation: Option<&CancellationToken>,
    deadline: Instant,
) -> Result<(), AdmissionStop> {
    let mut cursor = tree.walk();
    let mut depth = 1usize;
    let mut nodes = 0usize;
    let mut spans = 0usize;
    loop {
        stopped(cancellation, deadline)?;
        let node = cursor.node();
        nodes += 1;
        spans = spans.saturating_add(node.end_byte() - node.start_byte());
        check_limit(AdmissionDimension::Nodes, nodes, MAX_NODES)?;
        check_limit(AdmissionDimension::Depth, depth, MAX_DEPTH)?;
        check_limit(AdmissionDimension::SpanBytes, spans, MAX_SPAN_BYTES)?;
        if cursor.goto_first_child() {
            depth += 1;
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return validate_lines(adapter, source, tree, cancellation, deadline);
            }
            depth -= 1;
        }
    }
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
    let mut cursor = tree.walk();
    let mut bad_ancestors = 0usize;
    let mut ranges = Vec::new();
    let mut excluded_nodes = 0usize;
    loop {
        stopped(cancellation, deadline)?;
        let node = cursor.node();
        let bad = node.is_error() || node.is_missing();
        let first_line = overlong_lines.partition_point(|line| line.end <= node.start_byte());
        let intersects_overlong = overlong_lines
            .get(first_line)
            .is_some_and(|line| line.start < node.end_byte());
        let eligible = if intersects_overlong && bad_ancestors == 0 && !bad {
            let mut should_stop = || {
                cancellation.is_some_and(CancellationToken::is_cancelled)
                    || Instant::now() >= deadline
            };
            match adapter.is_structural_line_data(node, &mut should_stop) {
                ControlFlow::Continue(eligible) => eligible,
                ControlFlow::Break(()) => {
                    stopped(cancellation, deadline)?;
                    unreachable!("language admission hook stops only on cancellation/deadline")
                }
            }
        } else {
            false
        };
        if eligible {
            // A selected maximal subtree is not visited again by discovery.
            let mut data = node.walk();
            loop {
                stopped(cancellation, deadline)?;
                excluded_nodes += 1;
                check_limit(
                    AdmissionDimension::ExcludedNodes,
                    excluded_nodes,
                    MAX_EXCLUDED_NODES,
                )?;
                if data.goto_first_child() {
                    continue;
                }
                while !data.goto_next_sibling() {
                    if !data.goto_parent() {
                        break;
                    }
                }
                if data.node().id() == node.id() {
                    break;
                }
            }
            ranges.push(node.byte_range());
        } else if cursor.goto_first_child() {
            bad_ancestors += usize::from(bad);
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                // Discovery is preorder and skips selected subtrees: intervals
                // are already ordered, maximal and disjoint.
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
                    while first_range < ranges.len() && ranges[first_range].end <= offset {
                        first_range += 1;
                    }
                    let mut excluded = 0usize;
                    for range in &ranges[first_range..] {
                        if range.start >= end {
                            break;
                        }
                        excluded += range.end.min(end).saturating_sub(range.start.max(offset));
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
                return Ok(());
            }
            bad_ancestors -= usize::from(cursor.node().is_error() || cursor.node().is_missing());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::Language;
    use crate::analyzer::store::StoreLanguageAdapter;
    use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;

    struct PythonAdapter;
    impl StoreLanguageAdapter for PythonAdapter {
        fn language(&self) -> Language {
            Language::Python
        }
    }
    impl LanguageAdapter for PythonAdapter {
        fn query_directory(&self) -> &'static str {
            "python"
        }
        fn supports_structural_line_data(&self) -> bool {
            true
        }
        fn is_structural_line_data(
            &self,
            _node: tree_sitter::Node<'_>,
            _should_stop: &mut dyn FnMut() -> bool,
        ) -> std::ops::ControlFlow<(), bool> {
            std::ops::ControlFlow::Continue(true)
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
    fn tree_budget_counts_each_ast_node_once() {
        let source = "x = 1\n".repeat(9_000);
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(&source, None).unwrap();
        let mut cursor = tree.walk();
        let mut count = 0usize;
        loop {
            count += 1;
            if cursor.goto_first_child() {
                continue;
            }
            while !cursor.goto_next_sibling() {
                if !cursor.goto_parent() {
                    break;
                }
            }
            if cursor.node().id() == tree.root_node().id() {
                break;
            }
        }
        assert!(count > MAX_NODES / 2 && count < MAX_NODES, "{count}");
        assert!(
            validate_structural_envelope(
                &PythonAdapter,
                &source,
                &tree,
                None,
                Instant::now() + std::time::Duration::from_secs(30)
            )
            .is_ok()
        );
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
