//! Go rename from selected inverse edges.
//!
//! Edits are collected only from complete, proven native inverse rows. A
//! saved-state query over selected scopes, imports and package summaries
//! rejects captures and rebindings before returning the edit set.

use crate::analyzer::go::GoAnalyzer;
use brokk_bifrost_analysis::analyzer::rename::exact::{
    ExactRenameEditIssue, ExactRenameHooks, RenameAssemblyIssue, RenameAssemblyLimits,
    RenameSourceIssue, assemble_exact_rename, check_rename_authority,
};

use crate::analyzer::go::selected_reverse::GoSelectedReverseOutcome;

use crate::analyzer::go::selected_reverse::go_selected_inverse_for_rename_original;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::rename::MAX_RENAME_IDENTIFIER_BYTES;

use brokk_bifrost_analysis::analyzer::rename::RenameFailure;

use brokk_bifrost_analysis::analyzer::rename::RenameResult;

use brokk_bifrost_analysis::analyzer::resolution::seam_profile::GoRenamePhase;

use brokk_bifrost_analysis::analyzer::resolution::seam_profile::go_rename_phase;

use brokk_bifrost_analysis::analyzer::usages::finder::DEFAULT_MAX_FILES;

use brokk_bifrost_analysis::analyzer::usages::finder::DEFAULT_MAX_USAGES;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::project::Project;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

/// Native Go rename preparation. It remains outside Go production dispatch.
pub struct GoNativeRenameProvider;

impl brokk_bifrost_analysis::analyzer::rename::RenameProvider for GoNativeRenameProvider {
    fn rename(
        &self,
        analyzer: &dyn IAnalyzer,
        project: &dyn Project,
        target: &CodeUnit,
        new_name: &str,
    ) -> Result<RenameResult, RenameFailure> {
        let go = resolve_analyzer::<GoAnalyzer>(analyzer)
            .ok_or_else(|| failure("incomplete_analysis", "selected Go analyzer is unavailable"))?;
        native_go_rename(go, project, target, new_name, &CancellationToken::default())
    }
}

/// Test-support entry point for running Go's native rename implementation
/// without registering it in production language dispatch.
#[cfg(any(test, feature = "test-support"))]
pub fn go_native_rename(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    target: &CodeUnit,
    new_name: &str,
    cancellation: &CancellationToken,
) -> Result<RenameResult, RenameFailure> {
    let go = resolve_analyzer::<GoAnalyzer>(analyzer)
        .ok_or_else(|| failure("incomplete_analysis", "selected Go analyzer is unavailable"))?;
    native_go_rename(go, project, target, new_name, cancellation)
}

fn native_go_rename(
    go: &GoAnalyzer,
    project: &dyn Project,
    target: &CodeUnit,
    new_name: &str,
    cancellation: &CancellationToken,
) -> Result<RenameResult, RenameFailure> {
    use brokk_bifrost_analysis::analyzer::common::is_valid_rename_identifier;

    if target.source().declaration_language() != Language::Go {
        return Err(failure(
            "unsupported",
            "native Go rename requires a Go declaration",
        ));
    }
    if new_name.len() > MAX_RENAME_IDENTIFIER_BYTES
        || !is_valid_rename_identifier(Language::Go, new_name)
    {
        return Err(failure("invalid_name", "invalid Go replacement identifier"));
    }
    if cancellation.is_cancelled() {
        return Err(failure("cancelled", "native Go rename was cancelled"));
    }
    let snapshots = go.inner.selected_workspace_snapshots();
    let (Some(snapshot), Some(profile)) = (
        snapshots.get("go"),
        go.context_profile_for_file(&brokk_bifrost_core::path_utils::rel_path_string(
            target.source(),
        )),
    ) else {
        return Err(failure(
            "stale_context",
            "selected Go package/import context is unavailable",
        ));
    };
    let context = go
        .inner
        .analyzer_store()
        .selected_go_context(snapshot, &profile)
        .map_err(|error| failure("incomplete_analysis", error.to_string()))?
        .ok_or_else(|| {
            failure(
                "stale_context",
                "selected Go package/import context is unavailable",
            )
        })?;
    let generation = project.analysis_generation();
    let (original, conflict) =
        match go_selected_inverse_for_rename_original(go, target, new_name, cancellation) {
            (GoSelectedReverseOutcome::Ready(answer), conflict) => (answer, conflict),
            (
                GoSelectedReverseOutcome::Unavailable(reason)
                | GoSelectedReverseOutcome::TargetUncovered(reason),
                _,
            ) => {
                return Err(failure("incomplete_analysis", reason));
            }
            (GoSelectedReverseOutcome::Stale(reason), _) => {
                return Err(failure("incomplete_analysis", reason));
            }
            (GoSelectedReverseOutcome::Cancelled, _) => {
                return Err(failure("cancelled", "native Go rename was cancelled"));
            }
            (GoSelectedReverseOutcome::StoreError(reason), _) => {
                return Err(failure("incomplete_analysis", reason));
            }
        };
    if let Some(conflict) = conflict {
        return Err(conflict);
    }
    let edit_assembly_phase = go_rename_phase(GoRenamePhase::EditAssembly);
    let assembled = assemble_exact_rename(
        go,
        project,
        target,
        new_name,
        &original,
        RenameAssemblyLimits {
            max_usages: DEFAULT_MAX_USAGES,
            max_files: DEFAULT_MAX_FILES,
        },
        cancellation,
        &GoRenameHooks(go),
    )
    .map_err(rename_assembly_failure)?
    .ok_or_else(|| failure("cancelled", "native Go rename was cancelled"))?;
    let result = assembled.result;
    drop(edit_assembly_phase);
    if check_rename_authority(project, generation, cancellation).is_err() {
        return Err(failure(
            "incomplete_analysis",
            "native Go rename was cancelled or selected generation changed",
        ));
    }
    use brokk_bifrost_analysis::analyzer::store::go_package_context::GoContextHeadStatus;
    match go
        .inner
        .analyzer_store()
        .go_context_head_status(&context, cancellation)
        .map_err(|error| failure("incomplete_analysis", error.to_string()))?
    {
        GoContextHeadStatus::Current => Ok(result),
        GoContextHeadStatus::Withdrawn => Err(failure(
            "stale_context",
            "selected Go package/import publication was withdrawn",
        )),
        GoContextHeadStatus::Cancelled => {
            Err(failure("cancelled", "native Go rename was cancelled"))
        }
    }
}

struct GoRenameHooks<'a>(&'a GoAnalyzer);

impl ExactRenameHooks for GoRenameHooks<'_> {
    type FileState = ();

    fn admit_source(&self, file: &ProjectFile, source: &str) -> Result<(), RenameSourceIssue> {
        if !self
            .0
            .inner
            .source_matches_selected_native_content(file, source)
        {
            return Err(RenameSourceIssue::ContentChanged);
        }
        Ok(())
    }
}

fn rename_assembly_failure(issue: RenameAssemblyIssue<'_>) -> RenameFailure {
    let message = match issue {
        RenameAssemblyIssue::IncompleteInventory(result) => {
            format!("original Go inverse inventory is incomplete: {result:?}")
        }
        RenameAssemblyIssue::UnprovenInventory(result) => {
            format!("original Go inverse evidence is incomplete or unproven: {result:?}")
        }
        RenameAssemblyIssue::TooManyUsages(count) => {
            return failure(
                "too_many_callsites",
                format!("native Go rename exceeds the usage limit: {count}"),
            );
        }
        RenameAssemblyIssue::TooManyFiles => {
            return failure("too_many_files", "native Go rename exceeds the file limit");
        }
        RenameAssemblyIssue::ReadSource(error) => error.to_string(),
        RenameAssemblyIssue::Source {
            file,
            issue: RenameSourceIssue::ContentChanged,
        } => format!("native Go rename source differs from selected content: {file}"),
        RenameAssemblyIssue::Source {
            issue: RenameSourceIssue::ParseFailed,
            ..
        }
        | RenameAssemblyIssue::MissingReferenceName(_) => {
            unreachable!("Go rename uses exact inverse ranges without parsing")
        }
        RenameAssemblyIssue::MissingDeclarationName => {
            "native Go rename target has no structured declaration name".into()
        }
        RenameAssemblyIssue::RangeOutsideSource { file, range } => {
            format!("native Go inverse range is outside {file}: {range:?}")
        }
        RenameAssemblyIssue::DeclarationSpellingMismatch => {
            "native Go declaration range does not contain its structured identifier".into()
        }
        RenameAssemblyIssue::Edit(ExactRenameEditIssue::Overlap) => {
            "native Go rename edits overlap".into()
        }
        RenameAssemblyIssue::Edit(ExactRenameEditIssue::InexactReplacement(edit)) => {
            format!("native Go rename edit is not an exact identifier replacement: {edit:?}")
        }
    };
    failure("incomplete_analysis", message)
}

fn failure(kind: &'static str, message: impl Into<String>) -> RenameFailure {
    RenameFailure {
        kind,
        message: message.into(),
    }
}
