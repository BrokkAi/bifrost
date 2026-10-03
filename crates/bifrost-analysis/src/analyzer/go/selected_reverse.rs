//! Selected Go reverse references. Candidate names come from the sealed
//! reference-lookup identity index and Go package rows; every candidate is
//! resolved again through the selected file-scoped Go forward context.

use super::GoAnalyzer;
use crate::CancellationToken;
use crate::analyzer::resolution::ResolutionCompletion;
use crate::analyzer::store::resolution_operation::go_reverse_rows::{
    GoReverseBindingTarget, GoReverseCandidateOutcome, GoReverseConfirmed,
};
use crate::analyzer::store::resolution_operation::{
    SelectedResolutionContextMetrics, SelectedResolutionOperationInput,
    SelectedResolutionOperationOpenOutcome, SelectedResolutionOperationOutcome,
};
use crate::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;
use crate::analyzer::store::resolution_selection::SelectedResolutionLanguage;
use crate::analyzer::store::{Result, StoreError};
use crate::analyzer::structural::EdgeProvenance;
use crate::analyzer::structural::SiteClass;
use crate::analyzer::structural::reference_edges::{
    EdgeCompleteness, EdgeDerivationResult, EdgeIncompleteReason, EdgeSite, ReferenceEdgeRow,
    ReferenceSiteClassifier, classify_owner_relation,
};
use crate::analyzer::usages::{UsageHitKind, UsageProof};
use crate::analyzer::{
    CodeUnit, CodeUnitIndex, IAnalyzer, Language, ProjectFile, Range, resolve_analyzer,
};
use crate::hash::HashMap;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use brokk_bifrost_core::analyzer::go_facts::GoSourceTypeShape;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionCallableReceiverOrigin, ResolutionNamespace, ResolutionSiteKind,
};
use std::sync::Arc;

#[derive(Debug)]
pub enum GoSelectedReverseOutcome<T> {
    Ready(T),
    Unavailable(String),
    Stale(String),
    Cancelled,
    StoreError(String),
}

/// Resolve one target against the selected Go package/import inventory.
pub fn go_selected_inverse_for(
    go: &GoAnalyzer,
    target: &CodeUnit,
    cancellation: &CancellationToken,
) -> GoSelectedReverseOutcome<EdgeDerivationResult> {
    match go_selected_inverse_for_inner(go, target, cancellation) {
        Ok(outcome) => outcome,
        Err(error) => GoSelectedReverseOutcome::StoreError(error.to_string()),
    }
}

fn go_selected_inverse_for_inner(
    go: &GoAnalyzer,
    target: &CodeUnit,
    cancellation: &CancellationToken,
) -> Result<GoSelectedReverseOutcome<EdgeDerivationResult>> {
    if cancellation.is_cancelled() {
        return Ok(GoSelectedReverseOutcome::Cancelled);
    }
    let snapshots = go.inner.selected_workspace_snapshots();
    let Some(snapshot) = snapshots.get("go") else {
        return Ok(GoSelectedReverseOutcome::Unavailable(
            "the workspace has no selected Go snapshot".into(),
        ));
    };
    let Some(profile) = go.native_context_profile() else {
        return Ok(GoSelectedReverseOutcome::Unavailable(
            "the Go package/import profile is unavailable".into(),
        ));
    };
    let Some(context) = go
        .inner
        .analyzer_store()
        .selected_go_context(snapshot, &profile)?
    else {
        return Ok(GoSelectedReverseOutcome::Unavailable(
            "the selected Go package/import publication is unavailable".into(),
        ));
    };
    let (masks, content_mounts) = match go
        .inner
        .selected_resolution_overlay_inputs(snapshots.as_ref(), cancellation)?
    {
        SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        } => (masks, content_mounts),
        SelectedResolutionOverlayInputsOutcome::Unavailable(reason) => {
            return Ok(GoSelectedReverseOutcome::Unavailable(format!("{reason:?}")));
        }
        SelectedResolutionOverlayInputsOutcome::Stale(reason) => {
            return Ok(GoSelectedReverseOutcome::Stale(format!("{reason:?}")));
        }
        SelectedResolutionOverlayInputsOutcome::Cancelled => {
            return Ok(GoSelectedReverseOutcome::Cancelled);
        }
    };
    let languages = [SelectedResolutionLanguage::new("go", Language::Go)];
    let input = SelectedResolutionOperationInput::new(
        go.inner.project(),
        go.inner.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &masks,
    )
    .with_content_mounts(content_mounts);
    let operation = match go
        .inner
        .analyzer_store()
        .open_selected_resolution_operation(input, cancellation)?
    {
        SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
        SelectedResolutionOperationOpenOutcome::Unavailable(reason) => {
            return Ok(GoSelectedReverseOutcome::Unavailable(format!("{reason:?}")));
        }
        SelectedResolutionOperationOpenOutcome::Stale(reason) => {
            return Ok(GoSelectedReverseOutcome::Stale(format!("{reason:?}")));
        }
        SelectedResolutionOperationOpenOutcome::Cancelled => {
            return Ok(GoSelectedReverseOutcome::Cancelled);
        }
    };
    let generation = go.inner.project().analysis_generation();
    let candidates =
        match operation.go_reverse_candidate_sites(target, context.context_id, cancellation)? {
            GoReverseCandidateOutcome::Ready(candidates) => candidates,
            GoReverseCandidateOutcome::Unavailable(reason) => {
                return Ok(GoSelectedReverseOutcome::Unavailable(reason));
            }
            GoReverseCandidateOutcome::Cancelled => {
                return Ok(GoSelectedReverseOutcome::Cancelled);
            }
        };
    let mut context_metrics = SelectedResolutionContextMetrics;
    let confirmed = match operation.confirm_go_reverse_candidates(
        context.context_id,
        candidates,
        cancellation,
        &mut context_metrics,
    )? {
        SelectedResolutionOperationOutcome::Native(confirmed) => confirmed,
        SelectedResolutionOperationOutcome::Unavailable(reason) => {
            return Ok(GoSelectedReverseOutcome::Unavailable(format!("{reason:?}")));
        }
        SelectedResolutionOperationOutcome::Stale(reason) => {
            return Ok(GoSelectedReverseOutcome::Stale(format!("{reason:?}")));
        }
        SelectedResolutionOperationOutcome::Cancelled(_) => {
            return Ok(GoSelectedReverseOutcome::Cancelled);
        }
    };
    if go.inner.project().analysis_generation() != generation {
        return Ok(GoSelectedReverseOutcome::Stale(
            "Go selected reverse query crossed an analyzer generation".into(),
        ));
    }
    let answer = project_confirmed_references(go, target, generation, confirmed, cancellation)?;
    if go.inner.project().analysis_generation() != generation {
        return Ok(GoSelectedReverseOutcome::Stale(
            "Go selected reverse projection crossed an analyzer generation".into(),
        ));
    }
    Ok(GoSelectedReverseOutcome::Ready(answer))
}

fn project_confirmed_references(
    go: &GoAnalyzer,
    target: &CodeUnit,
    generation: u64,
    confirmed: GoReverseConfirmed,
    cancellation: &CancellationToken,
) -> Result<EdgeDerivationResult> {
    let mut reasons = Vec::new();
    if !confirmed.candidate_inventory_complete {
        reasons.push(EdgeIncompleteReason::InverseIndexReferenceEnumerationIncomplete);
    }
    if confirmed.completion != ResolutionCompletion::Complete {
        reasons.push(EdgeIncompleteReason::InverseIndexResolutionIncomplete);
    }
    let mut selected_aliases = Vec::new();
    for reference in &confirmed.references {
        let Some(metadata) = reference.answer.site_metadata() else {
            continue;
        };
        if metadata.site_kind() != ResolutionSiteKind::TypeReference
            || metadata.namespace() != ResolutionNamespace::Type
            || !reference
                .answer
                .binding()
                .targets()
                .contains(&confirmed.target)
        {
            continue;
        }
        selected_aliases.extend(qualified_alias_owners_for_reference(go, reference, target)?);
    }
    let mut files = HashMap::<ProjectFile, GoSelectedReferenceFile<'_>>::default();
    let mut edges = Vec::new();
    for reference in confirmed.references {
        if cancellation.is_cancelled() {
            return Err(StoreError::new("Go selected reverse query was cancelled"));
        }
        let answer = reference.answer;
        let Some(metadata) = answer.site_metadata() else {
            push_reason(
                &mut reasons,
                EdgeIncompleteReason::InverseIndexMetadataIncomplete,
            );
            continue;
        };
        let directly_bound = answer.binding().targets().contains(&confirmed.target);
        // Go aliases bind to their declaration spelling, while their selected
        // type frontier carries the aliased named type identity. Count that
        // only for a structured type-reference site; a value whose receiver
        // happens to have this type is not a reference to the type name.
        let transparent_type_alias = metadata.site_kind() == ResolutionSiteKind::TypeReference
            && metadata.namespace() == ResolutionNamespace::Type
            && (answer
                .projected_frontiers()
                .iter()
                .flat_map(|frontier| frontier.possible_values())
                .any(|value| value.ty().identity() == confirmed.target)
                || reference
                    .binding_targets
                    .iter()
                    .any(|alias| selected_aliases.contains(alias)));
        if !directly_bound && !transparent_type_alias {
            continue;
        }
        let file = ProjectFile::new(go.inner.project().root(), reference.locator.relative_path());
        if !files.contains_key(&file) {
            let source = go.indexed_source(&file).ok_or_else(|| {
                StoreError::new(format!(
                    "selected Go reference has no indexed source: {file}"
                ))
            })?;
            if !go
                .inner
                .source_matches_selected_native_content(&file, &source)
            {
                return Err(StoreError::new(format!(
                    "selected Go reference source changed before projection: {file}"
                )));
            }
            files.insert(
                file.clone(),
                GoSelectedReferenceFile::new(go, &file, &source),
            );
        }
        let projected_file = files.get(&file).expect("selected Go source was projected");
        let owner = reference.owner;
        if answer
            .reference_owner()
            .is_some_and(|owner| owner.is_some())
            && owner.is_none()
        {
            push_reason(
                &mut reasons,
                EdgeIncompleteReason::InverseIndexMetadataIncomplete,
            );
        }
        let owner_relation = classify_owner_relation(go, owner.as_ref(), target);
        let reference_kind = projected_file.classifier.as_ref().and_then(|classifier| {
            classifier.classify_reference_kind(metadata.start_byte(), metadata.end_byte(), target)
        });
        let ast_id = projected_file
            .classifier
            .as_ref()
            .and_then(|classifier| classifier.ast_id(metadata.start_byte(), metadata.end_byte()));
        if projected_file.classifier.is_none() {
            push_reason(
                &mut reasons,
                EdgeIncompleteReason::InverseIndexMetadataIncomplete,
            );
        }
        edges.push(ReferenceEdgeRow {
            site: EdgeSite {
                file,
                range: projected_file.range(metadata.start_byte(), metadata.end_byte()),
                ast_id,
                enclosing: owner,
            },
            target: target.clone(),
            reference_kind,
            proof: if directly_bound
                && answer.binding().targets().len() == 1
                && answer.binding().completion() == &ResolutionCompletion::Complete
            {
                UsageProof::Proven
            } else {
                UsageProof::Unproven
            },
            usage_kind: go_selected_usage_kind(metadata, owner_relation, target),
            site_class: SiteClass::UseSite,
            owner_relation,
            provenance: EdgeProvenance::Inverse,
            generation,
        });
    }
    Ok(EdgeDerivationResult {
        edges,
        completeness: if reasons.is_empty() {
            EdgeCompleteness::Complete
        } else {
            EdgeCompleteness::Incomplete { reasons }
        },
        provenance: EdgeProvenance::Inverse,
        generation,
    })
}

/// A direct `type Alias = pkg.Target` reference can be forward-confirmed at
/// the alias declaration even when the importing package's selected context
/// cannot project the alias type frontier. Keep that structured proof local to
/// this reverse query, then admit references that the selected forward pass
/// binds to that exact alias declaration.
fn qualified_alias_owners_for_reference(
    go: &GoAnalyzer,
    reference: &crate::analyzer::store::resolution_operation::go_reverse_rows::GoReverseConfirmedReference,
    target: &CodeUnit,
) -> Result<Vec<GoReverseBindingTarget>> {
    let Some(metadata) = reference.answer.site_metadata() else {
        return Ok(Vec::new());
    };
    let file = ProjectFile::new(go.inner.project().root(), reference.locator.relative_path());
    let Some(source) = go.indexed_source(&file) else {
        return Ok(Vec::new());
    };
    if !go
        .inner
        .source_matches_selected_native_content(&file, &source)
    {
        return Err(StoreError::new(format!(
            "selected Go alias source changed before reverse projection: {file}"
        )));
    }
    let Some(facts) = go
        .inner
        .canonical_go_source_facts(&file, &go.memo_caches.source_facts)
    else {
        return Ok(Vec::new());
    };
    let mut owners = Vec::new();
    for alias in &facts.facts.aliases {
        let Some(target_type) = alias.target else {
            continue;
        };
        let target_type = &facts.facts.types[target_type.index()];
        let GoSourceTypeShape::Named(name) = &target_type.shape else {
            continue;
        };
        if name.path().len() != 2
            || name.path().get(1).map(String::as_str) != Some(target.identifier())
        {
            continue;
        }
        let target_range = facts.source.occurrence(target_type.occurrence).range;
        if metadata.start_byte() < target_range.start_byte
            || metadata.end_byte() > target_range.end_byte
        {
            continue;
        }
        let declaration = facts.source.declaration(alias.declaration);
        let name = declaration
            .name
            .expect("a Go type alias declaration has a source name");
        owners.push(GoReverseBindingTarget::Lexical {
            source_file: file.clone(),
            name_range: facts.source.occurrence(name).range,
        });
        if let Some(units) = facts.declaration_units.get(&alias.declaration) {
            owners.extend(units.iter().cloned().map(GoReverseBindingTarget::Unit));
        }
    }
    Ok(owners)
}

fn push_reason(reasons: &mut Vec<EdgeIncompleteReason>, reason: EdgeIncompleteReason) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

struct GoSelectedReferenceFile<'analyzer> {
    source_len: usize,
    line_starts: Box<[usize]>,
    classifier: Option<ReferenceSiteClassifier<'analyzer>>,
}

impl<'analyzer> GoSelectedReferenceFile<'analyzer> {
    fn new(go: &'analyzer GoAnalyzer, file: &ProjectFile, source: &str) -> Self {
        Self {
            source_len: source.len(),
            line_starts: compute_line_starts(source).into_boxed_slice(),
            classifier: ReferenceSiteClassifier::new(go, file),
        }
    }

    fn range(&self, start_byte: usize, end_byte: usize) -> Range {
        assert!(
            start_byte <= end_byte && end_byte <= self.source_len,
            "selected Go reference range must fit indexed source: {start_byte}..{end_byte} of {}",
            self.source_len,
        );
        Range {
            start_byte,
            end_byte,
            start_line: find_line_index_for_offset(&self.line_starts, start_byte) + 1,
            end_line: find_line_index_for_offset(&self.line_starts, end_byte.saturating_sub(1)) + 1,
        }
    }
}

fn go_selected_usage_kind(
    metadata: crate::analyzer::resolution::FactReferenceSiteMetadata,
    owner_relation: crate::analyzer::structural::OwnerRelation,
    target: &CodeUnit,
) -> UsageHitKind {
    if metadata.site_kind() == ResolutionSiteKind::ImportDeclaration {
        UsageHitKind::Import
    } else if metadata.callable_receiver_origin()
        == Some(ResolutionCallableReceiverOrigin::CurrentInstance)
        || (owner_relation == crate::analyzer::structural::OwnerRelation::SelfReference
            && target.is_function())
        || (metadata.namespace() == ResolutionNamespace::Value
            && matches!(
                metadata.site_kind(),
                ResolutionSiteKind::ValueReference | ResolutionSiteKind::MemberReference
            )
            && owner_relation == crate::analyzer::structural::OwnerRelation::SelfReference)
    {
        UsageHitKind::SelfReceiver
    } else {
        UsageHitKind::Reference
    }
}

/// A generation-bound lazy facade. It retains the analyzer, not a workspace
/// sized inverse map; each target's SQL candidates and source projections die
/// with that target request.
pub struct GoNativeSelectedReferenceIndex {
    generation: u64,
    go: Box<GoAnalyzer>,
    cancellation: CancellationToken,
}

impl crate::analyzer::structural::reference_edges::SelectedInverseReferenceIndex
    for GoNativeSelectedReferenceIndex
{
    fn generation(&self) -> u64 {
        self.generation
    }

    fn inverse_for(&self, target: &CodeUnit) -> EdgeDerivationResult {
        if self.go.inner.project().analysis_generation() != self.generation {
            return incomplete_inverse(
                self.generation,
                EdgeIncompleteReason::InverseIndexResolutionIncomplete,
            );
        }
        match go_selected_inverse_for(&self.go, target, &self.cancellation) {
            GoSelectedReverseOutcome::Ready(answer) => answer,
            GoSelectedReverseOutcome::Unavailable(detail) => {
                eprintln!("selected Go inverse query unavailable: {detail}");
                incomplete_inverse(
                    self.generation,
                    EdgeIncompleteReason::InverseIndexTargetUncovered,
                )
            }
            GoSelectedReverseOutcome::Stale(detail) => {
                eprintln!("selected Go inverse query stale: {detail}");
                incomplete_inverse(
                    self.generation,
                    EdgeIncompleteReason::InverseIndexResolutionIncomplete,
                )
            }
            GoSelectedReverseOutcome::Cancelled => {
                incomplete_inverse(self.generation, EdgeIncompleteReason::Cancelled)
            }
            GoSelectedReverseOutcome::StoreError(detail) => {
                eprintln!("selected Go inverse query failed: {detail}");
                incomplete_inverse(
                    self.generation,
                    EdgeIncompleteReason::InverseIndexResolutionIncomplete,
                )
            }
        }
    }
}

fn incomplete_inverse(generation: u64, reason: EdgeIncompleteReason) -> EdgeDerivationResult {
    EdgeDerivationResult {
        edges: Vec::new(),
        completeness: EdgeCompleteness::Incomplete {
            reasons: vec![reason],
        },
        provenance: EdgeProvenance::Inverse,
        generation,
    }
}

pub struct GoNativeSelectedInverseProvider;

impl crate::analyzer::structural::reference_edges::SelectedInverseReferenceProvider
    for GoNativeSelectedInverseProvider
{
    fn build_selected_inverse_index(
        &self,
        analyzer: &dyn IAnalyzer,
        cancellation: Option<&CancellationToken>,
    ) -> crate::analyzer::structural::reference_edges::SelectedInverseIndexOutcome {
        use crate::analyzer::structural::reference_edges::SelectedInverseIndexOutcome;
        let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
            return SelectedInverseIndexOutcome::Unavailable(
                "the workspace has no Go analyzer".into(),
            );
        };
        let token = cancellation.cloned().unwrap_or_default();
        if token.is_cancelled() {
            return SelectedInverseIndexOutcome::Cancelled;
        }
        match selected_go_context_id(go) {
            Ok(Some(_)) => {
                SelectedInverseIndexOutcome::Ready(Arc::new(GoNativeSelectedReferenceIndex {
                    generation: go.inner.project().analysis_generation(),
                    go: Box::new(go.clone()),
                    cancellation: token,
                }))
            }
            Ok(None) => SelectedInverseIndexOutcome::Unavailable(
                "the selected Go package/import publication is unavailable".into(),
            ),
            Err(error) => SelectedInverseIndexOutcome::StoreError(error.to_string()),
        }
    }
}

fn selected_go_context_id(go: &GoAnalyzer) -> Result<Option<i64>> {
    let snapshots = go.inner.selected_workspace_snapshots();
    let Some(snapshot) = snapshots.get("go") else {
        return Ok(None);
    };
    let Some(profile) = go.native_context_profile() else {
        return Ok(None);
    };
    Ok(go
        .inner
        .analyzer_store()
        .selected_go_context(snapshot, &profile)?
        .map(|context| context.context_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::go::native_usages::GoNativeUsageStrategy;
    use crate::analyzer::{CodeUnitIndex, Project};
    use crate::hash::HashSet;
    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use crate::path_utils::rel_path_string;
    use std::collections::BTreeSet;

    const MODEL: &str = "model/model.go";
    const CLIENT: &str = "client/client.go";
    const NAMED: &str = "named/use.go";
    const DOT: &str = "dot/use.go";
    const EXTERNAL: &str = "model/external_test.go";

    const MODEL_SOURCE: &str = r#"package model

type Widget struct { Name string }

func (w Widget) Run() {}

func NewWidget() Widget { return Widget{} }

func NeverUsed() {}
func privateHelper() {}

func samePackage(w Widget) {
	_ = w.Name
	w.Run()
	_ = NewWidget()
	privateHelper()
}
"#;

    const CLIENT_SOURCE: &str = r#"package client

import alias "example.test/native/model"

func useAlias(w alias.Widget) {
	_ = w.Name
	w.Run()
	_ = alias.NewWidget()
}

func shadow() {
	NewWidget := func() int { return 1 }
	_ = NewWidget()
}
"#;

    const DOT_SOURCE: &str = r#"package dot

import . "example.test/native/model"

func useDot(w Widget) {
	_ = w.Name
	w.Run()
	_ = NewWidget()
}
"#;

    const NAMED_SOURCE: &str = r#"package named

import "example.test/native/model"

func useNamed(w model.Widget) {
	_ = w.Name
	w.Run()
	_ = model.NewWidget()
}
"#;

    const EXTERNAL_SOURCE: &str = r#"package model_test

import model "example.test/native/model"

func externalTest() {
	_ = model.Widget{}
	_ = model.NewWidget()
}
"#;

    fn fixture() -> (BuiltInlineTestProject, GoAnalyzer) {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/native\n\ngo 1.22\n")
            .file(MODEL, MODEL_SOURCE)
            .file(CLIENT, CLIENT_SOURCE)
            .file(NAMED, NAMED_SOURCE)
            .file(DOT, DOT_SOURCE)
            .file(EXTERNAL, EXTERNAL_SOURCE)
            .build();
        let analyzer = GoAnalyzer::new(fixture.project_dyn());
        persist_selected_go_sources(&analyzer);
        (fixture, analyzer)
    }

    fn persist_selected_go_sources(analyzer: &GoAnalyzer) {
        for file in analyzer.get_analyzed_files() {
            assert!(
                analyzer
                    .inner
                    .write_live_file_to_store_for_test(&file)
                    .is_some(),
                "persist Go resolution facts for {file}"
            );
        }
    }

    fn target(analyzer: &GoAnalyzer, fixture: &BuiltInlineTestProject, name: &str) -> CodeUnit {
        target_at(analyzer, fixture, MODEL, name)
    }

    fn target_at(
        analyzer: &GoAnalyzer,
        fixture: &BuiltInlineTestProject,
        path: &str,
        name: &str,
    ) -> CodeUnit {
        analyzer
            .declarations(&fixture.file(path))
            .into_iter()
            .find(|unit| unit.identifier() == name)
            .unwrap_or_else(|| panic!("missing Go declaration {name} in {path}"))
    }

    fn transitive_fixture(files: &[(&str, &str)]) -> (BuiltInlineTestProject, GoAnalyzer) {
        let mut builder = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/transitive\n\ngo 1.22\n");
        for (path, source) in files {
            builder = builder.file(*path, *source);
        }
        let fixture = builder.build();
        let analyzer = GoAnalyzer::new(fixture.project_dyn());
        persist_selected_go_sources(&analyzer);
        (fixture, analyzer)
    }

    fn inverse(analyzer: &GoAnalyzer, target: &CodeUnit) -> EdgeDerivationResult {
        match go_selected_inverse_for(analyzer, target, &CancellationToken::new()) {
            GoSelectedReverseOutcome::Ready(answer) => answer,
            outcome => panic!("selected Go inverse query failed: {outcome:?}"),
        }
    }

    fn edge_paths(answer: &EdgeDerivationResult) -> HashSet<String> {
        answer
            .edges
            .iter()
            .map(|edge| rel_path_string(&edge.site.file))
            .collect()
    }

    fn usage_hits(
        result: crate::analyzer::usages::FuzzyResult,
    ) -> (BTreeSet<crate::analyzer::usages::UsageHit>, bool) {
        use crate::analyzer::usages::FuzzyResult;

        let (hits_by_overload, unproven_by_overload, incomplete) = match result {
            FuzzyResult::Success {
                hits_by_overload,
                unproven_by_overload,
                ..
            } => (hits_by_overload, unproven_by_overload, false),
            FuzzyResult::Incomplete {
                hits_by_overload,
                unproven_by_overload,
                ..
            } => (hits_by_overload, unproven_by_overload, true),
            outcome => panic!("Go usage query produced no hit inventory: {outcome:?}"),
        };
        (
            hits_by_overload
                .into_values()
                .chain(unproven_by_overload.into_values())
                .flatten()
                .collect(),
            incomplete,
        )
    }

    fn assert_transitive_candidate_stays_incomplete(
        answer: &EdgeDerivationResult,
        expected_path: &str,
        scenario: &str,
    ) {
        let candidates = crate::analyzer::store::resolution_operation::go_reverse_rows::
            last_go_reverse_candidate_paths_for_test();
        assert!(
            candidates.iter().any(|path| path == expected_path),
            "{scenario} must reach the recursive candidate set for {expected_path}: {candidates:?}"
        );
        assert!(
            !edge_paths(answer).contains(expected_path),
            "forward resolution cannot yet type this {scenario}; do not publish a guessed edge: {answer:#?}"
        );
        assert!(
            matches!(
                &answer.completeness,
                EdgeCompleteness::Incomplete { reasons }
                    if reasons.contains(&EdgeIncompleteReason::InverseIndexResolutionIncomplete)
            ),
            "an unconfirmed {scenario} candidate must remain explicitly incomplete: {answer:#?}"
        );
    }

    #[test]
    fn selected_go_inverse_composes_package_peers_aliases_dot_imports_and_external_tests() {
        let (fixture, analyzer) = fixture();
        for (name, expected_paths) in [
            ("Widget", &[MODEL, CLIENT, NAMED, DOT, EXTERNAL][..]),
            ("Name", &[MODEL, CLIENT, NAMED, DOT][..]),
            ("Run", &[MODEL, CLIENT, NAMED, DOT][..]),
            ("NewWidget", &[MODEL, CLIENT, NAMED, DOT, EXTERNAL][..]),
        ] {
            let target = target(&analyzer, &fixture, name);
            let answer = inverse(&analyzer, &target);
            let paths = edge_paths(&answer);
            for expected in expected_paths {
                if *expected == EXTERNAL && !paths.contains(*expected) {
                    assert!(
                        matches!(
                            &answer.completeness,
                            EdgeCompleteness::Incomplete { reasons }
                                if reasons.contains(&EdgeIncompleteReason::InverseIndexResolutionIncomplete)
                        ),
                        "an unavailable external test package context must be reported as incomplete: {answer:#?}"
                    );
                    continue;
                }
                assert!(
                    paths.contains(*expected),
                    "{name} should have a confirmed edge from {expected}; answer={answer:#?}"
                );
            }
            assert!(
                answer.edges.iter().all(|edge| edge.target == target),
                "forward confirmation must publish only the exact target: {answer:#?}"
            );
            assert!(
                !answer.edges.iter().any(|edge| {
                    edge.site.file == fixture.file(CLIENT)
                        && edge.site.range.start_byte == CLIENT_SOURCE.find("NewWidget :=").unwrap()
                }),
                "the local NewWidget shadow must not bind to the package function: {answer:#?}"
            );
        }

        let private_target = target(&analyzer, &fixture, "privateHelper");
        let private_answer = inverse(&analyzer, &private_target);
        assert!(
            private_answer
                .edges
                .iter()
                .any(|edge| edge.site.file == fixture.file(MODEL)),
            "an unexported Go declaration remains visible in its package: {private_answer:#?}"
        );
        assert!(
            private_answer
                .edges
                .iter()
                .all(|edge| edge.site.file == fixture.file(MODEL)),
            "an unexported Go declaration is invisible outside its package: {private_answer:#?}"
        );
    }

    #[test]
    fn selected_go_inverse_includes_internal_test_package_variants() {
        const PROVIDER: &str = "package pkg\n\nfunc New() int { return 1 }\n";
        const INTERNAL_TEST: &str = r#"package pkg

import "testing"

func TestNew(t *testing.T) { _ = New() }
"#;
        let (fixture, analyzer) =
            transitive_fixture(&[("pkg/pkg.go", PROVIDER), ("pkg/pkg_test.go", INTERNAL_TEST)]);
        let target = target_at(&analyzer, &fixture, "pkg/pkg.go", "New");
        let answer = inverse(&analyzer, &target);
        let candidates = crate::analyzer::store::resolution_operation::go_reverse_rows::
            last_go_reverse_candidate_paths_for_test();
        assert!(
            candidates.iter().any(|path| path == "pkg/pkg_test.go"),
            "internal Go test package must be seeded as a same-package candidate: {candidates:?}"
        );
        assert!(
            answer
                .edges
                .iter()
                .any(|edge| edge.site.file == fixture.file("pkg/pkg_test.go")),
            "internal test call must resolve to its package declaration: {answer:#?}"
        );
        assert!(
            matches!(
                &answer.completeness,
                EdgeCompleteness::Incomplete { reasons }
                    if reasons.contains(&EdgeIncompleteReason::InverseIndexReferenceEnumerationIncomplete)
            ),
            "the source-inventory test-role fallback must remain explicitly incomplete: {answer:#?}"
        );
    }

    #[test]
    fn selected_go_inverse_follows_intermediate_package_for_methods() {
        const A: &str = r#"package a

type T struct{}

func (T) Method() {}
"#;
        const B: &str = r#"package b

import "example.test/transitive/a"

func Get() a.T { return a.T{} }
"#;
        const C: &str = r#"package c

import "example.test/transitive/b"

func use() {
	x := b.Get()
	x.Method()
}
"#;

        let (fixture, analyzer) =
            transitive_fixture(&[("a/a.go", A), ("b/b.go", B), ("c/c.go", C)]);
        let target = target_at(&analyzer, &fixture, "a/a.go", "Method");
        let answer = inverse(&analyzer, &target);
        assert_transitive_candidate_stays_incomplete(
            &answer,
            "c/c.go",
            "a method reached through b.Get",
        );
    }

    #[test]
    fn selected_go_inverse_follows_intermediate_package_for_promoted_members() {
        const A: &str = r#"package a

type T struct{}

func (T) Method() {}
"#;
        const B: &str = r#"package b

import "example.test/transitive/a"

type S struct { a.T }
"#;
        const C: &str = r#"package c

import "example.test/transitive/b"

func use(s b.S) {
	s.Method()
}
"#;

        let (fixture, analyzer) =
            transitive_fixture(&[("a/a.go", A), ("b/b.go", B), ("c/c.go", C)]);
        let target = target_at(&analyzer, &fixture, "a/a.go", "Method");
        let answer = inverse(&analyzer, &target);
        assert_transitive_candidate_stays_incomplete(
            &answer,
            "c/c.go",
            "a promoted method reached through b.S",
        );
    }

    #[test]
    fn selected_go_inverse_follows_intermediate_package_for_type_aliases() {
        const A: &str = r#"package a

type T struct { Value int }
"#;
        const B: &str = r#"package b

import "example.test/transitive/a"

type T = a.T
"#;
        const C: &str = r#"package c

import "example.test/transitive/b"

var value b.T
"#;

        let (fixture, analyzer) =
            transitive_fixture(&[("a/a.go", A), ("b/b.go", B), ("c/c.go", C)]);
        let target = target_at(&analyzer, &fixture, "a/a.go", "T");
        let answer = inverse(&analyzer, &target);
        let definition_plan = crate::analyzer::store::resolution_operation::go_reverse_rows::
            last_go_reverse_definition_plan_for_test();
        eprintln!("selected Go alias-definition EXPLAIN QUERY PLAN: {definition_plan:#?}");
        assert!(
            definition_plan
                .iter()
                .any(|detail| detail.contains("semantic")),
            "alias lexical projection must plan its populated semantic-site lookup: {definition_plan:#?}"
        );
        assert!(
            definition_plan
                .iter()
                .any(|detail| detail.contains("bridge")),
            "alias lexical projection must plan its populated source-declaration bridge lookup: {definition_plan:#?}"
        );
        assert!(
            definition_plan
                .iter()
                .any(|detail| detail.contains("declaration")),
            "alias lexical projection must plan its populated declaration-name lookup: {definition_plan:#?}"
        );
        let candidates = crate::analyzer::store::resolution_operation::go_reverse_rows::
            last_go_reverse_candidate_paths_for_test();
        assert!(
            candidates.iter().any(|path| path == "c/c.go"),
            "the transitive importer C must supply the type-alias candidate: {candidates:?}"
        );
        assert!(
            edge_paths(&answer).contains("c/c.go"),
            "the b.T type alias reference must be confirmed against a.T: {answer:#?}"
        );
        assert!(
            answer
                .edges
                .iter()
                .any(|edge| edge.site.file == fixture.file("c/c.go") && edge.target == target)
        );
        assert!(
            answer.edges.iter().all(|edge| edge.target == target),
            "publish only the selected a.T declaration: {answer:#?}"
        );
    }

    #[test]
    fn incomplete_go_package_inventory_never_publishes_complete_absence() {
        let (fixture, analyzer) = fixture();
        let snapshots = analyzer.inner.selected_workspace_snapshots();
        let snapshot = snapshots.get("go").expect("selected Go snapshot");
        let profile = analyzer.native_context_profile().expect("Go profile");
        let context = analyzer
            .inner
            .analyzer_store()
            .selected_go_context(snapshot, &profile)
            .unwrap()
            .expect("selected Go package context");
        let store = analyzer.inner.analyzer_store();
        crate::analyzer::store::resolution_operation::go_reverse_rows::
            mark_go_context_incomplete_for_test(store, context.context_id)
            .unwrap();

        let unused = target(&analyzer, &fixture, "NeverUsed");
        let answer = inverse(&analyzer, &unused);
        assert!(
            answer.edges.is_empty(),
            "the target has no reference sites: {answer:#?}"
        );
        assert!(
            matches!(answer.completeness, EdgeCompleteness::Incomplete { .. }),
            "an incomplete Go package publication cannot authorize an empty result: {answer:#?}"
        );
    }

    #[test]
    fn selected_go_strategy_uses_confirmed_inverse_sites_for_forward_usages() {
        use crate::analyzer::usages::UsageAnalyzer;

        let (fixture, analyzer) = fixture();
        let target = target(&analyzer, &fixture, "NewWidget");
        let admitted = analyzer
            .get_analyzed_files()
            .into_iter()
            .collect::<HashSet<_>>();
        let result = GoNativeUsageStrategy::new().find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &admitted,
            100,
        );
        let (hits, incomplete) = usage_hits(result);
        let hit_paths = hits
            .iter()
            .map(|hit| rel_path_string(&hit.file))
            .collect::<HashSet<_>>();
        assert!(hit_paths.contains(CLIENT), "{hits:#?}");
        assert!(hit_paths.contains(NAMED), "{hits:#?}");
        assert!(hit_paths.contains(DOT), "{hits:#?}");
        if !hit_paths.contains(EXTERNAL) {
            assert!(
                incomplete,
                "an unavailable external test package must not produce a complete absence: {hits:#?}"
            );
        }
        assert!(!hits.iter().any(|hit| {
            hit.file == fixture.file(CLIENT)
                && hit.start_offset == CLIENT_SOURCE.find("NewWidget :=").unwrap()
        }));
    }

    #[test]
    fn selected_go_usage_matches_incumbent_on_the_real_store_fixture() {
        use crate::analyzer::usages::{GoUsageGraphStrategy, UsageAnalyzer};

        let (_fixture, analyzer) = fixture();
        let admitted = analyzer
            .get_analyzed_files()
            .into_iter()
            .collect::<HashSet<_>>();
        for name in ["Widget", "Name", "Run", "NewWidget"] {
            let target = target(&analyzer, &_fixture, name);
            let legacy = GoUsageGraphStrategy::new().find_usages(
                &analyzer,
                std::slice::from_ref(&target),
                &admitted,
                100,
            );
            let native = GoNativeUsageStrategy::new().find_usages(
                &analyzer,
                std::slice::from_ref(&target),
                &admitted,
                100,
            );
            let (legacy, _) = usage_hits(legacy);
            let (native, native_incomplete) = usage_hits(native);
            let signatures = |hits: BTreeSet<crate::analyzer::usages::UsageHit>| {
                hits.into_iter()
                    .map(|hit| {
                        (
                            hit.file.rel_path().to_path_buf(),
                            hit.start_offset,
                            hit.end_offset,
                            hit.kind,
                        )
                    })
                    .collect::<BTreeSet<_>>()
            };
            let legacy = signatures(legacy);
            let native = signatures(native);
            let sites = |signatures: &BTreeSet<(
                std::path::PathBuf,
                usize,
                usize,
                crate::analyzer::usages::UsageHitKind,
            )>| {
                signatures
                    .iter()
                    .map(|(path, start, end, _)| (path.clone(), *start, *end))
                    .collect::<BTreeSet<_>>()
            };
            let legacy_sites = sites(&legacy);
            let native_sites = sites(&native);
            let legacy_only = legacy_sites.difference(&native_sites).collect::<Vec<_>>();
            let native_only = native_sites.difference(&legacy_sites).collect::<Vec<_>>();
            if !legacy_only.is_empty() || !native_only.is_empty() {
                assert!(
                    matches!(name, "Widget" | "NewWidget")
                        && native_incomplete
                        && native_only.is_empty()
                        && legacy_only
                            .iter()
                            .all(|(path, ..)| path.as_path() == std::path::Path::new(EXTERNAL)),
                    "source-adjudicate incumbent/native difference for {name}: legacy-only={legacy_only:?}, native-only={native_only:?}, incomplete={native_incomplete}"
                );
            }
            let native_kinds = native
                .iter()
                .map(|(path, start, end, kind)| ((path.clone(), *start, *end), *kind))
                .collect::<HashMap<_, _>>();
            let kind_differences = legacy
                .iter()
                .filter_map(|(path, start, end, legacy_kind)| {
                    native_kinds
                        .get(&(path.clone(), *start, *end))
                        .filter(|native_kind| *native_kind != legacy_kind)
                        .map(|native_kind| (path.clone(), *start, *end, *legacy_kind, *native_kind))
                })
                .collect::<BTreeSet<_>>();
            if !kind_differences.is_empty() {
                let receiver_site = MODEL_SOURCE
                    .find("func (w Widget)")
                    .expect("Go method receiver")
                    + "func (w ".len();
                assert_eq!(
                    name, "Widget",
                    "unexpected incumbent/native usage-kind difference: {kind_differences:?}"
                );
                assert_eq!(
                    kind_differences,
                    BTreeSet::from([(
                        std::path::PathBuf::from(MODEL),
                        receiver_site,
                        receiver_site + "Widget".len(),
                        crate::analyzer::usages::UsageHitKind::SelfReceiver,
                        crate::analyzer::usages::UsageHitKind::Reference,
                    )]),
                    "source-adjudicate Go's receiver-type kind difference"
                );
            }
        }
    }

    #[test]
    fn selected_go_inverse_provider_is_available_through_test_support_only() {
        use crate::analyzer::structural::reference_edges::{
            SelectedInverseIndexOutcome, SelectedInverseReferenceProvider,
        };

        let (fixture, analyzer) = fixture();
        let target = target(&analyzer, &fixture, "NewWidget");
        let index =
            match GoNativeSelectedInverseProvider.build_selected_inverse_index(&analyzer, None) {
                SelectedInverseIndexOutcome::Ready(index) => index,
                SelectedInverseIndexOutcome::Unavailable(reason) => {
                    panic!("Go test-support inverse provider unavailable: {reason}")
                }
                SelectedInverseIndexOutcome::Stale(reason) => {
                    panic!("Go test-support inverse provider stale: {reason}")
                }
                SelectedInverseIndexOutcome::Cancelled => {
                    panic!("Go test-support inverse provider cancelled")
                }
                SelectedInverseIndexOutcome::StoreError(reason) => {
                    panic!("Go test-support inverse provider failed: {reason}")
                }
            };
        assert_eq!(
            index.generation(),
            analyzer.inner.project().analysis_generation()
        );
        let answer = index.inverse_for(&target);
        assert!(
            answer
                .edges
                .iter()
                .any(|edge| edge.site.file == fixture.file(CLIENT)),
            "the lazy selected inverse index must answer from real-store rows: {answer:#?}"
        );
    }

    #[test]
    fn selected_go_reverse_reader_seeks_shared_identity_and_recursive_import_indexes() {
        let (fixture, analyzer) = fixture();
        let snapshots = analyzer.inner.selected_workspace_snapshots();
        let snapshot = snapshots.get("go").expect("selected Go snapshot");
        let profile = analyzer.native_context_profile().expect("Go profile");
        let context = analyzer
            .inner
            .analyzer_store()
            .selected_go_context(snapshot, &profile)
            .unwrap()
            .expect("selected Go package context");
        let store = analyzer.inner.analyzer_store();
        crate::analyzer::store::resolution_operation::go_reverse_rows::
            seed_go_reverse_plan_decoys_for_test(
                store,
                context.context_id,
                CLIENT,
                512,
            )
            .unwrap();
        store.refresh_planner_statistics().unwrap();

        let target = target(&analyzer, &fixture, "NewWidget");
        let answer = inverse(&analyzer, &target);
        assert!(!answer.edges.is_empty(), "{answer:#?}");
        let plan = crate::analyzer::store::resolution_operation::go_reverse_rows::
            last_go_reverse_candidate_plan_for_test();
        eprintln!("selected Go reverse candidate EXPLAIN QUERY PLAN: {plan:#?}");
        assert!(
            plan.iter()
                .any(|detail| detail.contains("resolution_reference_lookup_identities_identity")),
            "candidate sites must seek the shared reference identity index: {plan:#?}"
        );
        assert!(
            plan.iter().any(|detail| detail.contains("RECURSIVE STEP")),
            "exported-name discovery must execute a recursive importer closure: {plan:#?}"
        );
        assert!(
            plan.iter()
                .any(|detail| detail.contains("idx_go_package_imports_target")),
            "recursive importer discovery must seek the selected target-package index: {plan:#?}"
        );
        assert!(
            plan.iter()
                .any(|detail| detail.contains("resolution_qualified_routes_source_lookup")),
            "qualified terminal names must seek the selected route index: {plan:#?}"
        );
        assert!(
            plan.iter()
                .any(|detail| detail.contains("resolution_paths_root_terminal")),
            "prefixed root names must seek the selected root-terminal index: {plan:#?}"
        );
    }

    #[test]
    fn selected_go_native_incoming_calls_are_exactly_inverse_call_sites() {
        use crate::analyzer::QueryScope;
        use crate::analyzer::usages::UsageProofAuthority;
        use crate::analyzer::usages::call_relations::{CallRelationLimits, CallRelationService};
        use crate::analyzer::usages::get_definition::call_site_syntax_for_reference;

        let (fixture, analyzer) = fixture();
        let target = target(&analyzer, &fixture, "NewWidget");
        let selected = inverse(&analyzer, &target);
        let selected_complete = selected.completeness == EdgeCompleteness::Complete;

        let mut expected = BTreeSet::new();
        for edge in &selected.edges {
            let facts = analyzer
                .structural_fact_providers()
                .into_iter()
                .find_map(|provider| provider.structural_facts(&edge.site.file))
                .expect("real Go source has structural facts");
            if let Some(syntax) = call_site_syntax_for_reference(
                &facts,
                edge.site.range.start_byte,
                edge.site.range.end_byte,
            ) {
                expected.insert((
                    edge.site.file.clone(),
                    syntax.range.start_byte,
                    syntax.range.end_byte,
                ));
            }
        }

        let limits = CallRelationLimits {
            max_files: 64,
            max_source_bytes: 4 * 1024 * 1024,
            max_candidates: 256,
        };
        let native = super::super::native_call_relations::go_native_incoming_calls(
            &analyzer, &target, limits, None,
        );
        assert_eq!(native.proof_authority, UsageProofAuthority::Native);
        assert!(!native.cancelled && !native.truncated, "{native:#?}");
        assert_eq!(
            native.diagnostics.len(),
            if selected_complete { 0 } else { 2 },
            "the call projection carries the selected inverse inventory status: {native:#?}"
        );
        assert!(
            native.diagnostics.iter().all(|diagnostic| {
                diagnostic.reason_kind.as_deref() == Some("native_call_inventory_incomplete")
            }),
            "{native:#?}"
        );
        let actual = native
            .sites
            .iter()
            .map(|site| {
                (
                    site.file.clone(),
                    site.range.start_byte,
                    site.range.end_byte,
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            actual, expected,
            "native projection must preserve exactly the confirmed call rows"
        );

        let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
        let incumbent =
            CallRelationService::incoming_bounded(&analyzer, scope.token(), &target, limits, None);
        let incumbent_sites = incumbent
            .sites
            .iter()
            .map(|site| {
                (
                    site.file.clone(),
                    site.range.start_byte,
                    site.range.end_byte,
                )
            })
            .collect::<BTreeSet<_>>();
        let legacy_only = incumbent_sites
            .difference(&actual)
            .cloned()
            .collect::<BTreeSet<_>>();
        let native_only = actual
            .difference(&incumbent_sites)
            .cloned()
            .collect::<BTreeSet<_>>();
        let external_call = EXTERNAL_SOURCE
            .find("model.NewWidget()")
            .expect("external-test qualified call");
        let external_call_site = (
            fixture.file(EXTERNAL),
            external_call,
            external_call + "model.NewWidget()".len(),
        );
        assert!(
            incumbent_sites.contains(&external_call_site),
            "the incumbent recognizes the external-test package's qualified call"
        );
        assert!(
            actual.contains(&external_call_site),
            "the selected inverse projection confirms the external-test package's qualified call"
        );
        assert!(
            legacy_only.is_empty(),
            "incumbent-only calls: {legacy_only:?}"
        );
        assert!(
            native_only.is_empty(),
            "unexpected native-only calls: {native_only:?}"
        );
        assert!(
            !selected_complete
                && matches!(
                    &selected.completeness,
                    EdgeCompleteness::Incomplete { reasons }
                        if reasons.contains(&EdgeIncompleteReason::InverseIndexResolutionIncomplete)
                ),
            "external test package context is unavailable, so the native result remains explicitly incomplete: {selected:#?}"
        );
    }

    #[test]
    fn selected_go_native_rename_refuses_incomplete_qualified_multifile_inventory() {
        use crate::symbol_rename::{RenameSelection, rename_symbol};

        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/rename\n\ngo 1.22\n")
            .file("provider/api.go", "package provider\nfunc Helper() {}\n")
            .file("provider/other.go", "package provider\nfunc SamePackage() { Helper() }\n")
            .file(
                "client/one.go",
                "package client\nimport pkg \"example.test/rename/provider\"\nfunc One() { pkg.Helper() }\n",
            )
            .file(
                "client/two.go",
                "package client\nimport pkg \"example.test/rename/provider\"\nfunc Two() { pkg.Helper() }\n",
            )
            .build();
        let analyzer = GoAnalyzer::new(fixture.project_dyn());
        persist_selected_go_sources(&analyzer);
        let target = target_at(&analyzer, &fixture, "provider/api.go", "Helper");
        let native_error = super::super::native_rename::go_native_rename(
            &analyzer,
            fixture.project(),
            &target,
            "Assist",
            &CancellationToken::new(),
        )
        .expect_err("rename must refuse unresolved selected inverse evidence");
        assert_eq!(native_error.kind, "incomplete_analysis", "{native_error:?}");
        assert!(
            native_error
                .message
                .contains("InverseIndexReferenceEnumerationIncomplete")
                && native_error
                    .message
                    .contains("InverseIndexResolutionIncomplete"),
            "the refusal names both incomplete inventory sources: {native_error:?}"
        );

        let source = fixture
            .project()
            .read_source(&fixture.file("provider/api.go"))
            .expect("provider source");
        let declaration = source.find("Helper").expect("declaration name");
        let incumbent = rename_symbol(
            &analyzer,
            fixture.project(),
            fixture.file("provider/api.go"),
            RenameSelection::ByteOffset(declaration),
            "Assist",
        )
        .unwrap_or_else(|error| panic!("incumbent Go rename refused fixture: {error:?}"));
        let edits = |result: &crate::symbol_rename::RenameResult| {
            result
                .files
                .iter()
                .flat_map(|file| {
                    file.edits.iter().map(|edit| {
                        (
                            file.file.rel_path().to_path_buf(),
                            edit.start_byte,
                            edit.end_byte,
                            edit.new_text.clone(),
                        )
                    })
                })
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(
            incumbent
                .files
                .iter()
                .map(|file| file.file.rel_path().to_path_buf())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                std::path::PathBuf::from("provider/api.go"),
                std::path::PathBuf::from("provider/other.go"),
                std::path::PathBuf::from("client/one.go"),
                std::path::PathBuf::from("client/two.go"),
            ]),
            "the incumbent finds the declaration, same-package, and aliased cross-package references"
        );
        assert_eq!(
            edits(&incumbent).len(),
            4,
            "the incumbent's multi-file source edits are the adjudication baseline"
        );
        for file in incumbent
            .files
            .iter()
            .filter(|file| file.file.rel_path().starts_with("client"))
        {
            let source = fixture
                .project()
                .read_source(&file.file)
                .expect("aliased client source");
            for edit in &file.edits {
                assert_eq!(
                    source.get(edit.start_byte..edit.end_byte),
                    Some("Helper"),
                    "incumbent leaves import alias `pkg` untouched"
                );
            }
        }
    }

    #[test]
    fn selected_go_native_rename_refuses_incomplete_inventory_before_capture_check() {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/capture\n\ngo 1.22\n")
            .file(
                "main.go",
                "package capture\nfunc Original() {}\nfunc caller() { taken := 1; Original(); _ = taken }\n",
            )
            .build();
        let analyzer = GoAnalyzer::new(fixture.project_dyn());
        persist_selected_go_sources(&analyzer);
        let target = target_at(&analyzer, &fixture, "main.go", "Original");
        let selected = inverse(&analyzer, &target);
        assert!(matches!(
            selected.completeness,
            EdgeCompleteness::Incomplete { .. }
        ));
        let error = super::super::native_rename::go_native_rename(
            &analyzer,
            fixture.project(),
            &target,
            "taken",
            &CancellationToken::new(),
        )
        .expect_err("the local variable would capture the renamed call");
        assert_eq!(error.kind, "incomplete_analysis", "{error:?}");
        assert!(
            error
                .message
                .contains("InverseIndexReferenceEnumerationIncomplete")
                && error.message.contains("InverseIndexResolutionIncomplete"),
            "the incomplete source inventory blocks counterfactual capture analysis: {error:?}"
        );
    }
}
