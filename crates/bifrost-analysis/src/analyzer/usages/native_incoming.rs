//! Request-local projection of selected inverse rows into incoming calls.
//!
//! Languages retain source authority and operation publication. This assembler
//! never changes an edge's binding proof based on its source-level call shape.

use std::sync::Arc;

use crate::analyzer::structural::facts::FileFacts;
use crate::analyzer::structural::reference_edges::ReferenceEdgeRow;
use crate::analyzer::usages::call_relations::{
    CallRelationDiagnostic, CallRelationLimits, CallRelationResult, CallRelationWork, CallSite,
    is_call_relation_unit, raw_call_site,
};
use crate::analyzer::usages::get_definition::call_sites::{
    CallSiteSyntax, call_site_syntax_for_reference,
};
use crate::analyzer::usages::proof_rank;
use brokk_bifrost_core::analyzer::model::{CodeUnit, ProjectFile};
use brokk_bifrost_core::analyzer::usages::model::UsageProof;
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::HashMap;

/// A file's source-authority admission, cached only for this request.
pub enum IncomingFile {
    Rejected,
    Loaded(Option<Arc<FileFacts>>),
}

/// File and byte accounting shared by the language authority checks.
pub struct IncomingFileBudget<'a> {
    limits: CallRelationLimits,
    work: &'a mut CallRelationWork,
    truncated: &'a mut bool,
}

impl IncomingFileBudget<'_> {
    pub fn file_capacity_exhausted(&mut self) -> bool {
        let exhausted = self.work.scanned_files >= self.limits.max_files;
        *self.truncated |= exhausted;
        exhausted
    }

    pub fn source_fits(&mut self, bytes: usize) -> bool {
        let fits = bytes
            <= self
                .limits
                .max_source_bytes
                .saturating_sub(self.work.scanned_source_bytes);
        *self.truncated |= !fits;
        fits
    }

    pub fn admit_source(&mut self, bytes: usize) -> bool {
        if self.file_capacity_exhausted() || !self.source_fits(bytes) {
            return false;
        }
        self.work.scanned_files += 1;
        self.work.scanned_source_bytes += bytes;
        true
    }
}

/// Projection failures whose vocabulary belongs to the language.
pub enum IncomingProjectionIssue<'a> {
    FactsUnavailable(&'a ProjectFile),
    OwnerUnavailable(&'a ReferenceEdgeRow),
}

/// Source authority, owner rules and diagnostic vocabulary for incoming calls.
pub trait IncomingCallProjection {
    type Error;

    fn load_file(
        &mut self,
        file: &ProjectFile,
        budget: &mut IncomingFileBudget<'_>,
        diagnostics: &mut Vec<CallRelationDiagnostic>,
    ) -> Result<IncomingFile, Self::Error>;

    /// Language grammar may exclude references before charging a candidate.
    fn accept_reference(&self, _edge: &ReferenceEdgeRow, _syntax: &CallSiteSyntax) -> bool {
        true
    }

    fn caller(&self, edge: &ReferenceEdgeRow, _syntax: &CallSiteSyntax) -> Option<CodeUnit> {
        edge.site.enclosing.clone()
    }

    fn report_issue(&self, issue: IncomingProjectionIssue<'_>) -> CallRelationDiagnostic;
}

/// Pending calls and paired language metadata for exactly one requested target.
/// Only project_selected_incoming constructs this request-local collection.
pub struct IncomingSites<M>(Vec<(CallSite, usize, M)>);

/// Project rows for exactly one target, asserted on every selected edge.
/// Metadata remains paired until finish_incoming_sites removes duplicate calls.
///
/// None denotes cancellation. A selected-operation caller must discard its
/// provisional result on cancellation or error and publish only after Ready.
pub fn project_selected_incoming<'e, M, P: IncomingCallProjection>(
    projection: &mut P,
    target: &CodeUnit,
    rows: impl IntoIterator<Item = (&'e ReferenceEdgeRow, M)>,
    limits: CallRelationLimits,
    cancellation: &CancellationToken,
    result: &mut CallRelationResult,
) -> Result<Option<IncomingSites<M>>, P::Error> {
    let mut files = HashMap::default();
    let mut sites = Vec::new();
    for (edge, metadata) in rows {
        if cancellation.is_cancelled() {
            result.sites.clear();
            result.cancelled = true;
            return Ok(None);
        }
        assert_eq!(
            &edge.target, target,
            "reverse batch preserves target identity"
        );
        let file = &edge.site.file;
        if !files.contains_key(file) {
            let loaded = projection.load_file(
                file,
                &mut IncomingFileBudget {
                    limits,
                    work: &mut result.work,
                    truncated: &mut result.truncated,
                },
                &mut result.diagnostics,
            )?;
            // Missing facts are charged once but reported only once per file.
            let loaded = match loaded {
                IncomingFile::Loaded(None) => {
                    result.diagnostics.push(
                        projection.report_issue(IncomingProjectionIssue::FactsUnavailable(file)),
                    );
                    IncomingFile::Rejected
                }
                loaded => loaded,
            };
            files.insert(file.clone(), loaded);
        }
        let IncomingFile::Loaded(Some(facts)) = &files[file] else {
            continue;
        };
        let Some(syntax) = call_site_syntax_for_reference(
            facts,
            edge.site.range.start_byte,
            edge.site.range.end_byte,
        ) else {
            continue;
        };
        if !projection.accept_reference(edge, &syntax) {
            continue;
        }
        if result.work.examined_candidates >= limits.max_candidates {
            result.truncated = true;
            continue;
        }
        result.work.examined_candidates += 1;
        let Some(caller) = projection
            .caller(edge, &syntax)
            .filter(is_call_relation_unit)
        else {
            result
                .diagnostics
                .push(projection.report_issue(IncomingProjectionIssue::OwnerUnavailable(edge)));
            continue;
        };
        sites.push((
            raw_call_site(file.clone(), caller, target.clone(), syntax, edge.proof),
            sites.len(),
            metadata,
        ));
    }
    Ok(Some(IncomingSites(sites)))
}

/// Finalize calls for the one target asserted by project_selected_incoming.
/// Thus physical-range deduplication may omit the callee from its key.
/// Return only surviving unproven metadata, in its original acceptance order,
/// for language binding rechecks.
pub fn finish_incoming_sites<M>(
    IncomingSites(mut sites): IncomingSites<M>,
    result: &mut CallRelationResult,
) -> Vec<M> {
    sites.sort_by(|(left, _, _), (right, _, _)| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.range.start_byte.cmp(&right.range.start_byte))
            .then_with(|| left.range.end_byte.cmp(&right.range.end_byte))
            .then_with(|| left.caller.cmp(&right.caller))
            .then_with(|| left.callee.cmp(&right.callee))
            .then_with(|| proof_rank(left.proof).cmp(&proof_rank(right.proof)))
    });
    sites.dedup_by(|(left, _, _), (right, _, _)| {
        let same_range = left.file == right.file
            && left.range.start_byte == right.range.start_byte
            && left.range.end_byte == right.range.end_byte;
        if same_range {
            // One physical call range has one enclosing callable.
            debug_assert_eq!(left.caller, right.caller);
        }
        same_range
    });
    let mut unproven = Vec::new();
    for (site, ordinal, metadata) in sites {
        if site.proof != UsageProof::Proven {
            unproven.push((ordinal, metadata));
        }
        result.sites.push(site);
    }
    unproven.sort_unstable_by_key(|(ordinal, _)| *ordinal);
    unproven.into_iter().map(|(_, metadata)| metadata).collect()
}

/// Resolve the first structural caller, retaining the selected edge's owner fallback.
pub fn structural_incoming_caller<'a>(
    providers: impl IntoIterator<Item = &'a dyn crate::analyzer::structural::StructuralFactProvider>,
    edge: &ReferenceEdgeRow,
    syntax: &CallSiteSyntax,
) -> Option<CodeUnit> {
    providers
        .into_iter()
        .find_map(|provider| {
            provider
                .structural_enclosing_code_units(&edge.site.file, &[syntax.range])
                .and_then(|mut owners| owners.pop().flatten())
        })
        .or(edge.site.enclosing.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::usages::get_definition::call_sites::CallSyntaxKind;
    use brokk_bifrost_core::analyzer::model::{CodeUnitType, Range};
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#5658: duplicate unproven calls were rechecked despite a proven row")]
    fn binding_recheck_only_sees_surviving_unproven_calls() {
        let file = ProjectFile::new(std::env::temp_dir(), "incoming.rs");
        let caller = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "caller");
        let target = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "target");
        let site = |start_byte, proof| {
            let range = Range {
                start_byte,
                end_byte: start_byte + 8,
                start_line: 0,
                end_line: 0,
            };
            raw_call_site(
                file.clone(),
                caller.clone(),
                target.clone(),
                CallSiteSyntax {
                    range,
                    callee_range: range,
                    receiver: None,
                    arguments: Vec::new(),
                    kind: CallSyntaxKind::Function,
                },
                proof,
            )
        };
        // Input order must not let a weaker duplicate trigger binding work.
        let pending = IncomingSites(vec![
            (site(40, UsageProof::Unproven), 0, "first"),
            (site(20, UsageProof::Unproven), 1, "second"),
            (site(0, UsageProof::Unproven), 2, "shadowed"),
            (site(0, UsageProof::Proven), 3, "proven"),
            (site(20, UsageProof::Unproven), 4, "duplicate"),
        ]);
        let mut result = CallRelationResult::default();
        let recheck = finish_incoming_sites(pending, &mut result);
        assert_eq!(recheck, ["first", "second"]);
        assert_eq!(result.sites.len(), 3);
        assert_eq!(result.sites[0].range.start_byte, 0);
        assert_eq!(result.sites[0].proof, UsageProof::Proven);
        assert_eq!(result.sites[1].proof, UsageProof::Unproven);
    }
}
