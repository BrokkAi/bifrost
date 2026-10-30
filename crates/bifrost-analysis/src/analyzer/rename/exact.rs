//! Exact edits from one complete, proven native reference inventory.
//!
//! Capture proofs and selected-operation ownership stay with each language.
//! All sources and syntax state here belong to this bounded rename query.

use std::collections::BTreeMap;
use std::io;

use brokk_bifrost_core::cancellation::CancellationToken;

use crate::analyzer::declaration_range::code_unit_declaration_name_range;
use crate::analyzer::structural::reference_edges::{
    EdgeCompleteness, EdgeDerivationResult, EdgeSite,
};
use crate::analyzer::tree_sitter_analyzer::{LanguageAdapter, TreeSitterAnalyzer};
use crate::analyzer::{CodeUnit, IAnalyzer, Project, ProjectFile, Range};
use brokk_bifrost_core::analyzer::usages::model::UsageProof;

use super::{RenameEdit, RenameFileEdits, RenameResult};

pub struct RenameAssemblyLimits {
    pub max_usages: usize,
    pub max_files: usize,
}

pub struct AssembledExactRename {
    pub result: RenameResult,
    /// Includes admitted files whose references retain an alias spelling.
    pub sources: BTreeMap<ProjectFile, String>,
}

#[derive(Debug)]
pub enum ExactRenameEditIssue {
    Overlap,
    InexactReplacement(RenameEdit),
}

#[derive(Debug)]
pub enum RenameSourceIssue {
    ContentChanged,
    ParseFailed,
}

/// A checked coordinate segment for one edit in a counterfactual source.
/// Deltas are signed because replacements can grow or shrink the source.
pub struct RenameEditCoordinateSegment {
    /// Start of the replaced span in the original source.
    pub original_start: usize,
    /// End of the replaced span in the original source.
    pub original_end: usize,
    /// Start of the replacement span in the hypothetical source.
    pub hypothetical_start: usize,
    /// End of the replacement span in the hypothetical source.
    pub hypothetical_end: usize,
    /// Cumulative byte-length change before this edit.
    pub delta_before: i128,
    /// Cumulative byte-length change after this edit.
    pub delta_after: i128,
}

#[derive(Debug)]
pub struct RenameEditCoordinateError;

/// Lazily map sorted, non-overlapping original edits into hypothetical spans.
/// An arithmetic failure is yielded once and terminates the iterator.
pub struct RenameEditCoordinateSegments<'a> {
    edits: std::slice::Iter<'a, RenameEdit>,
    delta: i128,
    failed: bool,
}

impl<'a> RenameEditCoordinateSegments<'a> {
    #[track_caller]
    pub fn new(edits: &'a [RenameEdit]) -> Self {
        debug_assert!(
            edits.iter().all(|edit| edit.start_byte <= edit.end_byte),
            "rename edits have reversed ranges: {edits:?}"
        );
        Self {
            edits: edits.iter(),
            delta: 0,
            failed: false,
        }
    }
}

impl Iterator for RenameEditCoordinateSegments<'_> {
    type Item = Result<RenameEditCoordinateSegment, RenameEditCoordinateError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let edit = self.edits.next()?;
        let delta_before = self.delta;
        let checked = (|| {
            let original_start = edit.start_byte;
            let original_end = edit.end_byte;
            let hypothetical_start = usize::try_from(
                i128::try_from(original_start)
                    .ok()?
                    .checked_add(delta_before)?,
            )
            .ok()?;
            let hypothetical_end = hypothetical_start.checked_add(edit.new_text.len())?;
            let removed = i128::try_from(original_end.checked_sub(original_start)?).ok()?;
            let inserted = i128::try_from(edit.new_text.len()).ok()?;
            let delta_after = delta_before.checked_add(inserted.checked_sub(removed)?)?;
            Some(RenameEditCoordinateSegment {
                original_start,
                original_end,
                hypothetical_start,
                hypothetical_end,
                delta_before,
                delta_after,
            })
        })();
        match checked {
            Some(segment) => {
                self.delta = segment.delta_after;
                Some(Ok(segment))
            }
            None => {
                self.failed = true;
                Some(Err(RenameEditCoordinateError))
            }
        }
    }
}

/// Require the supplied source to match the selected native identity.
pub fn admit_selected_native_source<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    file: &ProjectFile,
    source: &str,
) -> Result<(), RenameSourceIssue> {
    if analyzer.source_matches_selected_native_content(file, source) {
        Ok(())
    } else {
        Err(RenameSourceIssue::ContentChanged)
    }
}

#[derive(Debug)]
pub enum RenameAssemblyIssue<'a> {
    IncompleteInventory(&'a EdgeDerivationResult),
    UnprovenInventory(&'a EdgeDerivationResult),
    TooManyUsages(usize),
    TooManyFiles,
    ReadSource(io::Error),
    Source {
        file: ProjectFile,
        issue: RenameSourceIssue,
    },
    MissingDeclarationName,
    MissingReferenceName(&'a EdgeSite),
    RangeOutsideSource {
        file: ProjectFile,
        range: Range,
    },
    DeclarationSpellingMismatch,
    Edit(ExactRenameEditIssue),
}

/// Language rules for one admitted source and one inverse reference site.
/// Hooks never traverse the inventory or assemble edits.
pub trait ExactRenameHooks {
    type FileState;

    fn admit_source(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> Result<Self::FileState, RenameSourceIssue>;

    fn reference_name_range(
        &self,
        _state: &Self::FileState,
        _source: &str,
        site: &EdgeSite,
        _target: &CodeUnit,
    ) -> Option<(usize, usize)> {
        Some((site.range.start_byte, site.range.end_byte))
    }
}

#[allow(clippy::too_many_arguments)]
pub fn assemble_exact_rename<'a, H: ExactRenameHooks>(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    target: &CodeUnit,
    new_name: &str,
    inventory: &'a EdgeDerivationResult,
    limits: RenameAssemblyLimits,
    cancellation: &CancellationToken,
    hooks: &H,
) -> Result<Option<AssembledExactRename>, RenameAssemblyIssue<'a>> {
    if inventory.completeness != EdgeCompleteness::Complete {
        return Err(RenameAssemblyIssue::IncompleteInventory(inventory));
    }
    if inventory
        .edges
        .iter()
        .any(|edge| edge.proof != UsageProof::Proven)
    {
        return Err(RenameAssemblyIssue::UnprovenInventory(inventory));
    }
    if inventory.edges.len() > limits.max_usages {
        return Err(RenameAssemblyIssue::TooManyUsages(inventory.edges.len()));
    }

    let mut files = BTreeMap::new();
    let admit =
        |files: &mut BTreeMap<_, _>, file: &ProjectFile| -> Result<(), RenameAssemblyIssue<'a>> {
            if files.contains_key(file) {
                return Ok(());
            }
            if files.len() >= limits.max_files {
                return Err(RenameAssemblyIssue::TooManyFiles);
            }
            let source = project
                .read_source(file)
                .map_err(RenameAssemblyIssue::ReadSource)?;
            let state =
                hooks
                    .admit_source(file, &source)
                    .map_err(|issue| RenameAssemblyIssue::Source {
                        file: file.clone(),
                        issue,
                    })?;
            files.insert(file.clone(), (source, state, Vec::<RenameEdit>::new()));
            Ok(())
        };
    admit(&mut files, target.source())?;
    let target_file = files
        .get(target.source())
        .expect("rename target was admitted");
    let declaration =
        code_unit_declaration_name_range(analyzer, target.source(), &target_file.0, target)
            .ok_or(RenameAssemblyIssue::MissingDeclarationName)?;

    for edge in &inventory.edges {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let file = &edge.site.file;
        admit(&mut files, file)?;
        let (source, state, edits) = files.get_mut(file).expect("rename source was admitted");
        let (start_byte, end_byte) = hooks
            .reference_name_range(state, source, &edge.site, target)
            .ok_or(RenameAssemblyIssue::MissingReferenceName(&edge.site))?;
        let spelling = source.get(start_byte..end_byte).ok_or_else(|| {
            RenameAssemblyIssue::RangeOutsideSource {
                file: file.clone(),
                range: edge.site.range,
            }
        })?;
        // Aliased references retain their independent spelling.
        if spelling == target.identifier() {
            edits.push(RenameEdit {
                start_byte,
                end_byte,
                new_text: new_name.to_owned(),
            });
        }
    }
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let (source, _, edits) = files
        .get_mut(target.source())
        .expect("rename target was admitted");
    if source.get(declaration.start_byte..declaration.end_byte) != Some(target.identifier()) {
        return Err(RenameAssemblyIssue::DeclarationSpellingMismatch);
    }
    edits.push(RenameEdit {
        start_byte: declaration.start_byte,
        end_byte: declaration.end_byte,
        new_text: new_name.to_owned(),
    });

    let mut sources = BTreeMap::new();
    let mut rename_files = Vec::new();
    for (file, (source, _, mut edits)) in files {
        edits.sort_by_key(|edit| (edit.start_byte, edit.end_byte));
        // Go ordinary/test package variants retain an answer per candidate:
        // crates/bifrost-store/src/analyzer/store/resolution_operation/go_reverse_rows.rs:2474,3067
        // crates/bifrost-go-analysis/src/analyzer/go/selected_reverse.rs:1064 preserves those rows.
        // Dropping same-range edits is lossless: each replaces exactly the old
        // name with the same new name, so the edits are identical.
        edits.dedup_by(|dropped, kept| {
            let same_range =
                (dropped.start_byte, dropped.end_byte) == (kept.start_byte, kept.end_byte);
            if same_range {
                debug_assert_eq!(
                    (dropped.start_byte, dropped.end_byte, &dropped.new_text),
                    (kept.start_byte, kept.end_byte, &kept.new_text)
                );
            }
            same_range
        });
        check_exact_rename_edits(&source, &edits, target.identifier(), new_name)
            .map_err(RenameAssemblyIssue::Edit)?;
        sources.insert(file.clone(), source);
        if !edits.is_empty() {
            rename_files.push(RenameFileEdits { file, edits });
        }
    }
    Ok(Some(AssembledExactRename {
        result: RenameResult {
            target: target.clone(),
            old_name: target.identifier().to_owned(),
            files: rename_files,
        },
        sources,
    }))
}

/// Validate ascending edits without modifying them. The caller owns sorting
/// and duplicate admission; Rust also uses this on its later safety reread.
pub fn check_exact_rename_edits(
    source: &str,
    edits: &[RenameEdit],
    old_name: &str,
    new_name: &str,
) -> Result<(), ExactRenameEditIssue> {
    if edits
        .windows(2)
        .any(|pair| pair[1].start_byte < pair[0].end_byte)
    {
        return Err(ExactRenameEditIssue::Overlap);
    }
    for edit in edits {
        if edit.new_text != new_name || source.get(edit.start_byte..edit.end_byte) != Some(old_name)
        {
            return Err(ExactRenameEditIssue::InexactReplacement(edit.clone()));
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct RenameAuthorityChanged;

pub fn check_rename_authority(
    project: &dyn Project,
    generation: u64,
    cancellation: &CancellationToken,
) -> Result<(), RenameAuthorityChanged> {
    if cancellation.is_cancelled() || project.analysis_generation() != generation {
        return Err(RenameAuthorityChanged);
    }
    Ok(())
}
