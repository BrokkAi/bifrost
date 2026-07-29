use super::{
    CodeQueryRange, CodeQuerySemanticCompleteness, CodeQuerySemanticEvidence,
    CodeQuerySemanticProof,
};
use crate::analyzer::semantic::{
    EvidenceCompleteness, LengthDelimitedDigest, ProofStatus, SemanticLocator,
};
use crate::analyzer::{ProjectFile, WorkspaceAnalyzer};
use crate::text_utils::{compute_line_starts, line_column_for_offset};

pub(super) fn retain_prefix_by_bytes<T>(
    items: impl IntoIterator<Item = T>,
    max_items: usize,
    max_bytes: usize,
    measure: impl Fn(&T) -> usize,
) -> (Vec<T>, usize, usize) {
    let mut items = items.into_iter();
    let mut retained = Vec::new();
    let mut retained_bytes = 0usize;
    while let Some(item) = items.next() {
        let item_bytes = measure(&item);
        if retained.len() >= max_items || item_bytes > max_bytes.saturating_sub(retained_bytes) {
            let omitted = 1usize.saturating_add(items.count());
            return (retained, retained_bytes, omitted);
        }
        retained_bytes = retained_bytes.saturating_add(item_bytes);
        retained.push(item);
    }
    (retained, retained_bytes, 0)
}

pub(super) fn locator_file(
    workspace: &WorkspaceAnalyzer,
    locator: &SemanticLocator,
) -> ProjectFile {
    ProjectFile::new(
        workspace.analyzer().project().root().to_path_buf(),
        locator.path().as_path(),
    )
}

pub(super) fn locator_range(
    workspace: &WorkspaceAnalyzer,
    locator: &SemanticLocator,
) -> CodeQueryRange {
    let span = locator.anchor().span();
    let file = locator_file(workspace, locator);
    let Some(source) = workspace.analyzer().indexed_source(&file) else {
        return CodeQueryRange {
            start_line: span.start().line() as usize + 1,
            start_column: span.start().byte_column() as usize + 1,
            end_line: span.end().line() as usize + 1,
            end_column: span.end().byte_column() as usize + 1,
        };
    };
    let line_starts = compute_line_starts(&source);
    let (start_line, start_column) =
        line_column_for_offset(&source, &line_starts, span.start_byte() as usize);
    let (end_line, end_column) =
        line_column_for_offset(&source, &line_starts, span.end_byte() as usize);
    CodeQueryRange {
        start_line,
        start_column,
        end_line,
        end_column,
    }
}

pub(super) fn public_evidence(
    proof: &ProofStatus,
    completeness: &EvidenceCompleteness,
) -> CodeQuerySemanticEvidence {
    CodeQuerySemanticEvidence {
        proof: match proof {
            ProofStatus::Proven => CodeQuerySemanticProof::Proven,
            ProofStatus::Unproven(_) => CodeQuerySemanticProof::Unproven,
        },
        proof_reason: match proof {
            ProofStatus::Proven => None,
            ProofStatus::Unproven(reason) => Some(bounded_reason(reason)),
        },
        completeness: match completeness {
            EvidenceCompleteness::Complete => CodeQuerySemanticCompleteness::Complete,
            EvidenceCompleteness::Partial(_) => CodeQuerySemanticCompleteness::Partial,
        },
        completeness_reason: match completeness {
            EvidenceCompleteness::Complete => None,
            EvidenceCompleteness::Partial(reason) => Some(bounded_reason(reason)),
        },
    }
}

pub(super) fn bounded_reason(reason: &str) -> String {
    const MAX_REASON_CHARS: usize = 256;
    let mut chars = reason.chars();
    let mut bounded = chars.by_ref().take(MAX_REASON_CHARS).collect::<String>();
    if chars.next().is_some() {
        bounded.push('…');
    }
    bounded
}

pub(super) fn hash_public_locator(digest: &mut LengthDelimitedDigest, locator: &SemanticLocator) {
    digest.push(locator.path().as_str().as_bytes());
    digest.push(locator.language().config_label().as_bytes());
    for segment in locator.declaration().segments() {
        digest.push(segment.kind().stable_label().as_bytes());
        digest.push(segment.name().unwrap_or("").as_bytes());
        digest.push_anchor(segment.anchor());
        digest.push(&segment.sibling_ordinal().to_le_bytes());
    }
    digest.push(locator.role().stable_label().as_bytes());
    digest.push_anchor(locator.anchor());
}

pub(super) fn saturating_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{bounded_reason, retain_prefix_by_bytes};

    #[test]
    fn byte_trimming_keeps_a_contiguous_prefix() {
        let (retained, retained_bytes, omitted) =
            retain_prefix_by_bytes(["aaaa", "bbbbbb", "c"], 3, 5, |value| value.len());

        assert_eq!(retained, ["aaaa"]);
        assert_eq!(retained_bytes, 4);
        assert_eq!(omitted, 2);
    }

    #[test]
    fn zero_step_projection_omits_the_whole_witness() {
        let (retained, retained_bytes, omitted) =
            retain_prefix_by_bytes(["first", "second"], 0, usize::MAX, |value| value.len());

        assert!(retained.is_empty());
        assert_eq!(retained_bytes, 0);
        assert_eq!(omitted, 2);
    }

    #[test]
    fn bounded_reasons_mark_omitted_text() {
        let reason = "x".repeat(257);
        let bounded = bounded_reason(&reason);
        assert_eq!(bounded.chars().count(), 257);
        assert!(bounded.ends_with('…'));
    }
}
