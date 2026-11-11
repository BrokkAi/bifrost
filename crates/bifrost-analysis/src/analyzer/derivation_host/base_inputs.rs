use brokk_bifrost_semantic::analyzer::semantic::derivation::BaseInputs;
use brokk_bifrost_semantic::analyzer::semantic::read_ledger::{
    FactSubject, LookupKind, LookupQuestion, ReadKey, WorkspaceFactFamily,
};
use brokk_bifrost_store::analyzer::store::reader_binding::ReaderBinding;

use super::authority::AnalyzerAuthority;
use crate::analyzer::{IAnalyzer, Language};

/// Verify head identities against the analyzer bound to this demand: the
/// active model set, a file's indexed blob and parse variant, and overlay
/// membership. Each is decided from main state alone, never a stage, so it
/// verifies with or without one. Selected-reader evidence for the other keys
/// is not available here yet.
pub struct VerifyHeadIdentityBaseInputs;

/// The read kinds this verifier decides exactly. Every other recorded read is
/// refused, so an entry that made one recomputes.
fn verifiable(read: &ReadKey) -> bool {
    matches!(
        read,
        ReadKey::Models(_)
            | ReadKey::File { .. }
            | ReadKey::PathAbsent { .. }
            | ReadKey::Lookup {
                kind: LookupKind::WorkspaceFact,
                question: LookupQuestion::WorkspaceFact {
                    family: WorkspaceFactFamily::WorkspaceOverlayMembership,
                    ..
                },
                ..
            }
    )
}

/// Whether `rel_path` still resolves, in `language`, to the blob and parse
/// variant the recording read. The blob is the live one, as the read recorded
/// it: the project's file snapshot, so an unsaved overlay's text counts, not
/// the blob the analyzer indexed. This differs on purpose from
/// `read_verification`, which prefers the blob the head analyzes for a path
/// in its diff set: a kept call-site entry is reused within a warm process
/// against whatever text the request now sees, so the live snapshot decides.
fn file_unchanged(
    analyzer: &dyn IAnalyzer,
    language: Language,
    rel_path: &str,
    blob: git2::Oid,
    parse_variant: brokk_bifrost_core::gitblob::ParseVariant,
) -> bool {
    brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
        let project = analyzer.project();
        let Some(file) = project.file_by_rel_path(std::path::Path::new(rel_path)) else {
            return false;
        };
        brokk_bifrost_core::analyzer::common::workspace_language_for_file(&file) == language
            && project
                .read_file_snapshot(&file)
                .is_ok_and(|snapshot| snapshot.oid() == blob)
            && analyzer.selected_parse_variant(&file) == Some(parse_variant)
    })
}

impl BaseInputs<ReaderBinding, AnalyzerAuthority> for VerifyHeadIdentityBaseInputs {
    fn unchanged(
        &self,
        read: &ReadKey,
        _: &ReaderBinding,
        _: &ReaderBinding,
        _: &AnalyzerAuthority,
    ) -> bool {
        match read {
            // A request can pin its model snapshot and its overlay apart, and
            // either one may carry the model set a compute read. The read
            // verifies only while both name the recorded set, so a snapshot
            // pinned without an overlay (or the reverse) fails closed.
            ReadKey::Models(recorded) => super::with_current_analyzer(|analyzer| {
                crate::analyzer::i_analyzer::current_model_set_read_digest(analyzer)
                    == Some(*recorded)
            }),
            ReadKey::File {
                language,
                rel_path,
                blob,
                parse_variant,
            } => super::with_current_analyzer(|analyzer| {
                file_unchanged(analyzer, *language, rel_path, *blob, *parse_variant)
            }),
            ReadKey::PathAbsent { rel_path, .. } => super::with_current_analyzer(|analyzer| {
                analyzer
                    .project()
                    .file_by_rel_path(std::path::Path::new(rel_path.as_ref()))
                    .is_none()
            }),
            // The same answers read_verification replays for overlay membership.
            ReadKey::Lookup {
                kind: LookupKind::WorkspaceFact,
                question:
                    LookupQuestion::WorkspaceFact {
                        family: WorkspaceFactFamily::WorkspaceOverlayMembership,
                        language: Language::None,
                        subject,
                    },
                digest,
            } => super::with_current_analyzer(|analyzer| match subject {
                FactSubject::Whole => {
                    crate::analyzer::workspace_authority::workspace_overlay_set_answer(
                        analyzer.project(),
                    ) == *digest
                }
                FactSubject::File { rel_path } => {
                    crate::analyzer::workspace_authority::workspace_overlay_membership_answer(
                        analyzer.project(),
                        rel_path,
                    ) == *digest
                }
                _ => false,
            }),
            ReadKey::Index { .. }
            | ReadKey::Lookup { .. }
            | ReadKey::Artifact { .. }
            | ReadKey::Scope { .. }
            | ReadKey::Policy { .. }
            | ReadKey::Configuration(..)
            | ReadKey::Epoch(..) => false,
        }
    }

    /// The reads `unchanged` decides from main state alone (the active model
    /// set, a file's indexed blob, overlay membership) verify here too. Every
    /// other read is refused, so this never accepts what `unchanged` refuses.
    fn unchanged_without_stage(
        &self,
        read: &ReadKey,
        since: &ReaderBinding,
        at: &ReaderBinding,
        authority: &AnalyzerAuthority,
    ) -> bool {
        verifiable(read) && self.unchanged(read, since, at, authority)
    }
}
