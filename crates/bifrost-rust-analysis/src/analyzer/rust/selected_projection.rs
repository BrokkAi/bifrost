//! Shared selected Rust reference-site projection helpers.
//!
//! These helpers are deliberately independent of diagnostic shadow worlds so
//! native selected consumers can retain the same source ranges, classifiers,
//! and usage-kind semantics after those worlds are removed.

use crate::analyzer::rust::RustAnalyzer;

use brokk_bifrost_analysis::analyzer::resolution::batch::FactReferenceSiteMetadata;

use brokk_bifrost_core::analyzer::structural::edges::OwnerRelation;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::ReferenceSiteClassifier;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::SelectedReferenceFileState;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::is_same_owner_member_reference;

use brokk_bifrost_core::analyzer::usages::model::UsageHitKind;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::model::Range;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionCallableReceiverOrigin, ResolutionNamespace, ResolutionSiteKind,
};

pub(crate) fn rust_selected_workspace_identity_gap(rust: &RustAnalyzer) -> Option<String> {
    (!rust.inner.workspace_declaration_identities_authoritative()).then(|| {
        format!(
            "selected Rust package identity inputs are not authoritative: {:?}",
            rust.inner.project().overlay_content()
        )
    })
}

pub(crate) struct RustSelectedReferenceFile<'analyzer> {
    source_len: usize,
    line_starts: Box<[usize]>,
    pub(crate) classifier: Option<ReferenceSiteClassifier<'analyzer>>,
}

impl<'analyzer> RustSelectedReferenceFile<'analyzer> {
    pub(crate) fn new(rust: &'analyzer RustAnalyzer, file: &ProjectFile, source: &str) -> Self {
        let selected = SelectedReferenceFileState::new(rust, file, source);
        Self {
            source_len: selected.source_len,
            line_starts: selected.line_starts,
            classifier: selected.classifier,
        }
    }

    pub(crate) fn range(&self, start_byte: usize, end_byte: usize) -> Range {
        assert!(
            start_byte <= end_byte && end_byte <= self.source_len,
            "selected Rust reference range must fit its indexed source: {start_byte}..{end_byte} of {}",
            self.source_len,
        );
        brokk_bifrost_core::analyzer::semantic_diagnostics::range_for_byte_span(
            &self.line_starts,
            start_byte,
            end_byte,
        )
    }
}

/// Classify one selected reference site onto the usage-kind surface its
/// structured facts prove.
///
/// A callable site whose producer-recorded receiver origin names the current
/// instance (`self` in Rust, `this` in Java) is a self receiver: the origin is
/// lowered from the reference site's receiver AST field, so it separates
/// `self.target()` from `other.target()` inside one owner, which the ownership
/// relation alone cannot do. A `SelfReceiver` hit stays editor-visible and is
/// excluded from the external usage surface and the external usage cap.
pub(crate) fn rust_selected_usage_kind(
    metadata: FactReferenceSiteMetadata,
    owner_relation: OwnerRelation,
    target: &CodeUnit,
) -> UsageHitKind {
    if metadata.site_kind() == ResolutionSiteKind::ImportDeclaration {
        UsageHitKind::Import
    } else if (metadata.callable_receiver_origin()
        == Some(ResolutionCallableReceiverOrigin::CurrentInstance))
        || (owner_relation == OwnerRelation::SelfReference && target.is_function())
        || (metadata.namespace() == ResolutionNamespace::Value
            && matches!(
                metadata.site_kind(),
                ResolutionSiteKind::ValueReference | ResolutionSiteKind::MemberReference
            )
            && (owner_relation == OwnerRelation::SelfReference
                || (metadata.unqualified()
                    && is_same_owner_member_reference(owner_relation, target))))
    {
        UsageHitKind::SelfReceiver
    } else {
        UsageHitKind::Reference
    }
}
