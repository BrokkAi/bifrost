use std::fmt::Write as _;

use sha2::{Digest, Sha256};

use crate::finding::{PolicyByteSpan, PolicyDisplayRegion, PolicySourceLocation};
use brokk_bifrost_analysis::analyzer::semantic::{ProcedureHandle, ProgramPointHandle, SemanticLocator};
use brokk_bifrost_analysis::analyzer::{ProjectFile, WorkspaceAnalyzer};
use brokk_bifrost_analysis::text_utils::{compute_line_starts, line_column_for_offset};

pub(super) fn policy_location(
    workspace: &WorkspaceAnalyzer,
    locator: &SemanticLocator,
) -> Result<PolicySourceLocation, String> {
    let span = locator.anchor().span();
    let file = ProjectFile::new(
        workspace.analyzer().project().root().to_path_buf(),
        locator.path().as_path(),
    );
    let (start_line, start_column, end_line, end_column) = workspace
        .analyzer()
        .indexed_source(&file)
        .map(|source| {
            let starts = compute_line_starts(&source);
            let (start_line, start_column) =
                line_column_for_offset(&source, &starts, span.start_byte() as usize);
            let (end_line, end_column) =
                line_column_for_offset(&source, &starts, span.end_byte() as usize);
            (start_line, start_column, end_line, end_column)
        })
        .unwrap_or_else(|| {
            (
                span.start().line() as usize + 1,
                span.start().byte_column() as usize + 1,
                span.end().line() as usize + 1,
                span.end().byte_column() as usize + 1,
            )
        });
    Ok(PolicySourceLocation::span(
        locator.path().clone(),
        PolicyByteSpan::new(u64::from(span.start_byte()), u64::from(span.end_byte()))
            .map_err(|error| error.to_string())?,
        PolicyDisplayRegion::new(
            start_line as u64,
            start_column as u64,
            end_line as u64,
            end_column as u64,
        )
        .map_err(|error| error.to_string())?,
    ))
}

pub(super) fn program_point_locator(point: &ProgramPointHandle) -> &SemanticLocator {
    let row = point
        .procedure()
        .semantics()
        .point(point.id())
        .expect("validated policy witness point resolves");
    &point
        .procedure()
        .semantics()
        .source_mapping(row.source)
        .expect("validated policy witness point has a source mapping")
        .locator
}

pub(super) fn semantic_root_key(root: &ProcedureHandle) -> String {
    let mut bytes = Vec::new();
    let locator = root.semantics().locator();
    bytes.extend_from_slice(locator.path().as_str().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(locator.language().config_label().as_bytes());
    bytes.push(0);
    append_declaration_identity(locator, &mut bytes);
    stable_hex(&bytes)
}

pub(super) fn semantic_site_key(
    workspace: &WorkspaceAnalyzer,
    locator: &SemanticLocator,
) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(semantic_root_key_from_locator(locator).as_bytes());
    bytes.extend_from_slice(locator.role().stable_label().as_bytes());
    let span = locator.anchor().span();
    let file = ProjectFile::new(
        workspace.analyzer().project().root().to_path_buf(),
        locator.path().as_path(),
    );
    if let Some(source) = workspace.analyzer().indexed_source(&file)
        && let Some(slice) = source.get(span.start_byte() as usize..span.end_byte() as usize)
    {
        bytes.extend_from_slice(slice.as_bytes());
    }
    bytes.extend_from_slice(&locator.anchor().occurrence().to_le_bytes());
    stable_hex(&bytes)
}

fn semantic_root_key_from_locator(locator: &SemanticLocator) -> String {
    let mut bytes = Vec::new();
    append_declaration_identity(locator, &mut bytes);
    stable_hex(&bytes)
}

fn append_declaration_identity(locator: &SemanticLocator, bytes: &mut Vec<u8>) {
    for segment in locator.declaration().segments() {
        bytes.extend_from_slice(segment.kind().stable_label().as_bytes());
        bytes.push(0);
        if let Some(name) = segment.name() {
            bytes.extend_from_slice(name.as_bytes());
        }
        bytes.extend_from_slice(&segment.sibling_ordinal().to_le_bytes());
    }
}

pub(super) fn stable_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String is infallible");
    }
    encoded
}
