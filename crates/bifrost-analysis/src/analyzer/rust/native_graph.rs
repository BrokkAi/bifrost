//! Native Rust broad consumer preparation for the production workspace graph provider.

use super::RustAnalyzer;
use crate::CancellationToken;
use crate::analyzer::languages::{EdgePassId, LanguageEdgeFailure, NativeWorkspaceGraphProvider};
use crate::analyzer::resolution::{
    FactReferenceEdgeDeclarationDomain, FactResolutionBatchSummary, ResolutionCompletion,
};
use crate::analyzer::store::Result;
use crate::analyzer::store::resolution_operation::{
    SelectedResolutionContextMetrics, SelectedResolutionOperationInput,
    SelectedResolutionOperationOpenOutcome, SelectedResolutionOperationOutcome,
    SelectedRustContextOutcome,
};
use crate::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;
use crate::analyzer::store::resolution_selection::SelectedResolutionLanguage;
use crate::analyzer::structural::reference_edges::{EdgeCompleteness, EdgeIncompleteReason};
use crate::analyzer::usages::workspace_graph::{
    NativeWorkspaceUsageGraphAccumulator, SelectedWorkspaceUsageGraphProjection,
    SelectedWorkspaceUsageGraphProjectionOutcome, UsageEcosystem, WorkspaceUsageCatalog,
    is_graph_declaration,
};
use crate::analyzer::{CodeUnitIndex, IAnalyzer, Language, ProjectFile, resolve_analyzer};
use crate::hash::HashSet;
use std::path::PathBuf;

pub(crate) enum RustNativeWorkspaceGraphOutcome {
    Complete(SelectedWorkspaceUsageGraphProjection),
    Incomplete(SelectedWorkspaceUsageGraphProjection),
    Cancelled,
    Stale(String),
    Unavailable(String),
}

pub(super) struct RustNativeWorkspaceGraphProvider;

impl NativeWorkspaceGraphProvider for RustNativeWorkspaceGraphProvider {
    fn id(&self) -> EdgePassId {
        EdgePassId::Rust
    }

    /// Live Rust blobs whose canonical facts were never published cannot
    /// contribute a reference, and the native projection cannot tell that
    /// absence from a file with no references. Reporting it here is what keeps
    /// "canonical Rust facts unavailable" from rendering as a complete empty
    /// graph.
    ///
    /// The question is asked of `request_files` alone. Rust publication is per
    /// blob, so a request's availability is decided by the blobs it resolves:
    /// a rooted request is unavailable only when one of its own files is
    /// unpublished, and an unrooted one still asks about every analyzable
    /// file, which is where the workspace-wide answer was the honest one.
    fn input_failure(
        &self,
        analyzer: &dyn IAnalyzer,
        request_files: &[ProjectFile],
    ) -> Option<LanguageEdgeFailure> {
        let rust = resolve_analyzer::<RustAnalyzer>(analyzer)?;
        match rust.rust_files_without_facts_among(request_files) {
            Ok(files) if files.is_empty() => None,
            Ok(files) => Some(LanguageEdgeFailure {
                reason: "canonical Rust facts are unavailable for live files",
                files,
            }),
            Err(error) => {
                rust.inner.record_store_error(error.context(
                    "checking canonical Rust publication before native workspace graph projection",
                ));
                Some(LanguageEdgeFailure {
                    reason: "canonical Rust fact publication could not be checked",
                    files: Vec::new(),
                })
            }
        }
    }

    fn project(
        &self,
        analyzer: &dyn IAnalyzer,
        admitted_callers: &[ProjectFile],
        cancellation: &CancellationToken,
    ) -> Result<SelectedWorkspaceUsageGraphProjectionOutcome> {
        let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(
                "selected Rust analyzer is unavailable".into(),
            ));
        };
        Ok(
            match build_rust_native_workspace_graph_for_files(
                rust,
                admitted_callers,
                crate::analyzer::resolution::MAX_REFERENCE_SEEDS_PER_BATCH,
                cancellation,
            )? {
                RustNativeWorkspaceGraphOutcome::Complete(graph) => {
                    SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph)
                }
                RustNativeWorkspaceGraphOutcome::Incomplete(graph) => {
                    SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph)
                }
                RustNativeWorkspaceGraphOutcome::Cancelled => {
                    SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled
                }
                RustNativeWorkspaceGraphOutcome::Stale(reason) => {
                    debug_assert!(!reason.is_empty());
                    SelectedWorkspaceUsageGraphProjectionOutcome::Stale
                }
                RustNativeWorkspaceGraphOutcome::Unavailable(reason) => {
                    SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason)
                }
            },
        )
    }
}

/// Project outgoing edges from exactly the supplied caller files. Definitions
/// in dependencies remain available, and only returned endpoints join the
/// rooted node catalog. A depth traversal can call this for each caller frontier.
pub(crate) fn build_rust_native_workspace_graph_for_files(
    rust: &RustAnalyzer,
    root_files: &[ProjectFile],
    maximum_batch_size: usize,
    cancellation: &CancellationToken,
) -> Result<RustNativeWorkspaceGraphOutcome> {
    build_rust_native_workspace_graph_with_progress(
        rust,
        root_files,
        maximum_batch_size,
        cancellation,
        &mut || {},
    )
}

/// Fold admitted files once through the canonical edge projector and shared
/// graph reducer. Every staged row remains private until operation authority
/// and the final analyzer generation check both pass.
fn build_rust_native_workspace_graph_with_progress(
    rust: &RustAnalyzer,
    root_files: &[ProjectFile],
    maximum_batch_size: usize,
    cancellation: &CancellationToken,
    progress: &mut dyn FnMut(),
) -> Result<RustNativeWorkspaceGraphOutcome> {
    if cancellation.is_cancelled() {
        return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
    }
    let generation = rust.project().analysis_generation();
    let snapshots = rust.inner.selected_workspace_snapshots();
    let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
    let (masks, content_mounts) = match rust
        .inner
        .selected_rust_resolution_overlay_inputs(snapshots.as_ref(), cancellation)?
    {
        SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        } => (masks, content_mounts),
        SelectedResolutionOverlayInputsOutcome::Cancelled => {
            return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
        }
        SelectedResolutionOverlayInputsOutcome::Stale(reason) => {
            return Ok(RustNativeWorkspaceGraphOutcome::Stale(format!(
                "{reason:?}"
            )));
        }
        SelectedResolutionOverlayInputsOutcome::Unavailable(reason) => {
            return Ok(RustNativeWorkspaceGraphOutcome::Unavailable(format!(
                "{reason:?}"
            )));
        }
    };
    let input = SelectedResolutionOperationInput::new(
        rust.inner.project(),
        rust.inner.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &masks,
    )
    .with_content_mounts(content_mounts);
    let mut operation = match rust
        .inner
        .analyzer_store()
        .open_selected_resolution_operation(input, cancellation)?
    {
        SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
        SelectedResolutionOperationOpenOutcome::Cancelled => {
            return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
        }
        SelectedResolutionOperationOpenOutcome::Stale(reason) => {
            return Ok(RustNativeWorkspaceGraphOutcome::Stale(format!(
                "{reason:?}"
            )));
        }
        SelectedResolutionOperationOpenOutcome::Unavailable(reason) => {
            return Ok(RustNativeWorkspaceGraphOutcome::Unavailable(format!(
                "{reason:?}"
            )));
        }
    };
    let mut admitted_callers = HashSet::default();
    for file in root_files {
        if cancellation.is_cancelled() {
            return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
        }
        admitted_callers.insert(file.clone());
    }
    let mut units = Vec::new();
    let mut seen_files = HashSet::default();
    for file in root_files {
        if cancellation.is_cancelled() {
            return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
        }
        if seen_files.insert(file) {
            let Some(catalog) = WorkspaceUsageCatalog::build_for_files_with_cancellation(
                rust,
                std::slice::from_ref(file),
                cancellation,
            ) else {
                return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
            };
            units.extend(catalog.nodes.into_iter().map(|node| node.primary));
        }
    }
    let mut declarations = Vec::new();
    for unit in units {
        if cancellation.is_cancelled() {
            return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
        }
        let ranges = rust.ranges(&unit);
        declarations.push((unit, ranges));
    }
    let mut rooted_declarations = declarations
        .iter()
        .map(|(unit, _)| unit.clone())
        .collect::<HashSet<_>>();
    let mut rooted_rows = Vec::new();
    // The names this build's unresolved bindings spell. A forward-resolution
    // gap is evidence about the declarations one of these names reaches and
    // about no others, so the projection carries them and a dead-code consumer
    // abstains per candidate instead of discarding the whole pass.
    let mut unresolved_names = std::collections::BTreeSet::new();
    let mut unresolved_names_complete = true;
    let mut reasons = Vec::new();
    let mut reference_count = 0;
    let mut edge_count = 0;
    let mut batch_count = 0;
    let mut stage = |batch: &crate::analyzer::resolution::FactReferenceEdgeBatch| {
        assert_eq!(batch.generation(), generation);
        let status = batch.domain_status(FactReferenceEdgeDeclarationDomain::TypeOrCallable);
        if let EdgeCompleteness::Incomplete {
            reasons: batch_reasons,
        } = status.completeness()
        {
            for reason in batch_reasons {
                if !reasons.contains(reason) {
                    reasons.push(reason.clone());
                }
            }
        }
        for row in batch.edges() {
            for unit in row
                .site
                .enclosing
                .iter()
                .chain(std::iter::once(&row.target))
            {
                if is_graph_declaration(unit) && rooted_declarations.insert(unit.clone()) {
                    declarations.push((unit.clone(), rust.ranges(unit)));
                }
            }
        }
        match batch.unresolved_names() {
            Some(names) => {
                for name in names {
                    unresolved_names.insert(name.clone());
                }
            }
            None => unresolved_names_complete = false,
        }
        rooted_rows.extend_from_slice(batch.edges());
        reference_count += batch.reference_count();
        edge_count += batch.edges().len();
        batch_count += 1;
        progress();
        Ok(())
    };
    // The build walks one crate at a time. Each crate's context answers only
    // the requested files that crate compiles, and it is dropped before the
    // next crate is read; nothing keyed by mount or crate survives an
    // iteration. What the build carries across them is its own result: the
    // staged edge rows and the combined summary. A file compiled into more
    // than one Cargo target is resolved once per crate, and the rows
    // deduplicate by endpoint. A request that names one file walks the one or
    // two crates that compile it, exactly as it did before; a request that
    // names the whole workspace no longer merges every crate's bridges into
    // one context.
    //
    // The last scope names no crate. Its files are the requested files no
    // selected crate compiles: they own no crate module, so no crate context
    // could compile a bridge out of them, and an empty crate set reads their
    // declaration access exactly as the whole-crate-set policy did.
    let mut summary = FactResolutionBatchSummary::empty();
    let mut scopes = operation
        .rust_crate_keys_for_files(
            admitted_callers.iter().map(ProjectFile::rel_path),
            cancellation,
        )?
        .into_iter()
        .map(Some)
        .collect::<Vec<_>>();
    scopes.push(None);
    let mut outside_crates = admitted_callers.clone();
    for scope in scopes {
        if cancellation.is_cancelled() {
            return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
        }
        let (keys, files) = match scope {
            Some(key) => {
                let mut files = HashSet::default();
                for member in operation.rust_crate_member_paths(key, cancellation)? {
                    let file = ProjectFile::new(rust.project().root(), PathBuf::from(member));
                    if admitted_callers.contains(&file) {
                        outside_crates.remove(&file);
                        files.insert(file);
                    }
                }
                (vec![key], files)
            }
            None => (Vec::new(), std::mem::take(&mut outside_crates)),
        };
        if files.is_empty() {
            continue;
        }
        // This crate's export, placement and membership answers, shared by
        // its context and its batches and dropped at the end of the iteration.
        let _crate_memos = operation.crate_stage_memos()?;
        let context =
            match operation.rust_context_for_crate_files(keys.clone(), &files, cancellation)? {
                SelectedRustContextOutcome::Ready(context) => context,
                SelectedRustContextOutcome::Cancelled => {
                    return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
                }
            };
        let staged = match operation.stage_rust_reference_edge_batches_in_files(
            rust,
            context,
            &keys,
            &files,
            maximum_batch_size,
            cancellation,
            &mut SelectedResolutionContextMetrics,
            &mut stage,
        )? {
            SelectedResolutionOperationOutcome::Native(summary) => summary,
            SelectedResolutionOperationOutcome::Cancelled(_) => {
                return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
            }
            SelectedResolutionOperationOutcome::Stale(reason) => {
                return Ok(RustNativeWorkspaceGraphOutcome::Stale(format!(
                    "{reason:?}"
                )));
            }
            SelectedResolutionOperationOutcome::Unavailable(reason) => {
                return Ok(RustNativeWorkspaceGraphOutcome::Unavailable(format!(
                    "{reason:?}"
                )));
            }
        };
        summary.accumulate(staged);
    }
    let completion = summary
        .completion()
        .combine(summary.reference_enumeration_completion());
    let summary = match operation.finish_native(summary, &completion, cancellation)? {
        SelectedResolutionOperationOutcome::Native(summary) => summary,
        SelectedResolutionOperationOutcome::Cancelled(_) => {
            return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
        }
        SelectedResolutionOperationOutcome::Stale(reason) => {
            return Ok(RustNativeWorkspaceGraphOutcome::Stale(format!(
                "{reason:?}"
            )));
        }
        SelectedResolutionOperationOutcome::Unavailable(reason) => {
            return Ok(RustNativeWorkspaceGraphOutcome::Unavailable(format!(
                "{reason:?}"
            )));
        }
    };
    if cancellation.is_cancelled() {
        return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
    }
    assert_eq!(reference_count, summary.reference_count());
    assert_eq!(batch_count, summary.batch_count());
    if summary.reference_enumeration_completion() != &ResolutionCompletion::Complete
        && !reasons.contains(&EdgeIncompleteReason::ReferenceEnumerationIncomplete)
    {
        reasons.push(EdgeIncompleteReason::ReferenceEnumerationIncomplete);
    }
    let completeness = if reasons.is_empty() {
        EdgeCompleteness::Complete
    } else {
        EdgeCompleteness::Incomplete { reasons }
    };
    let Some(mut accumulator) = NativeWorkspaceUsageGraphAccumulator::new(
        declarations,
        generation,
        UsageEcosystem::Rust,
        &admitted_callers,
        cancellation,
    ) else {
        return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
    };
    if !accumulator.stage(&rooted_rows, cancellation) {
        return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
    }
    if !accumulator.note_unresolved_names(
        unresolved_names_complete.then_some(&unresolved_names),
        cancellation,
    ) {
        return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
    }
    let projection = accumulator.finish(&completeness, &summary, edge_count, cancellation);
    if cancellation.is_cancelled() {
        return Ok(RustNativeWorkspaceGraphOutcome::Cancelled);
    }
    if rust.project().analysis_generation() != generation {
        return Ok(RustNativeWorkspaceGraphOutcome::Stale(
            "analyzer generation changed during native graph projection".into(),
        ));
    }
    Ok(match projection {
        SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph) => {
            RustNativeWorkspaceGraphOutcome::Complete(graph)
        }
        SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph) => {
            RustNativeWorkspaceGraphOutcome::Incomplete(graph)
        }
        SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled => {
            RustNativeWorkspaceGraphOutcome::Cancelled
        }
        SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason) => {
            RustNativeWorkspaceGraphOutcome::Unavailable(reason)
        }
        SelectedWorkspaceUsageGraphProjectionOutcome::Stale => {
            unreachable!("a reducer has no source authority to mark stale")
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::IAnalyzer;
    use crate::inline_project::InlineTestProject;
    use std::cell::Cell;

    /// A macro argument that reaches the graph only through a selected
    /// textual-macro capsule must still project its edge, and one such file
    /// must not cost the workspace every Rust edge it has.
    ///
    /// The capsule is lowered onto its host file's fragment and then
    /// specialized by the invocation's capture digest, so that two capsules in
    /// one host do not collide; `remount` rewrites the semantic and copies the
    /// capsule-local site id through. `project_fact_reference_edge_batch` used
    /// to recompute `reference_semantic(fragment, site)` and refuse any batch
    /// that disagreed, which is every capsule reference by construction. Lane
    /// IV measured it on tract: the 63rd projection call failed and the whole
    /// `usage_graph` request returned an analyzer store failure.
    ///
    /// The macro must be defined in a different file from its use, because
    /// `lower_macro_invocation` returns early when the invocation matches a
    /// macro visible in the same file, and so publishes no capsule at all.
    /// The invocation must be in expression position, as tract's `dispatch_*!`
    /// uses are.
    #[test]
    fn native_rust_usage_graph_projects_an_argument_of_a_cross_file_macro() {
        use crate::searchtools::{UsageGraphParams, usage_graph};

        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"capsule\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/macros.rs",
                concat!(
                    "macro_rules! dispatch {\n",
                    "    ($($path:ident)::* ($dt:expr) ($($args:expr),*)) => {{\n",
                    "        match $dt {\n",
                    "            0 => $($path)::*::<i8>($($args),*),\n",
                    "            _ => $($path)::*::<i16>($($args),*),\n",
                    "        }\n",
                    "    }};\n",
                    "}\n",
                ),
            )
            .file(
                "src/lib.rs",
                concat!(
                    "#[macro_use]\n",
                    "mod macros;\n",
                    "pub struct Tensor;\n",
                    "impl Tensor {\n",
                    "    pub fn datum_type(&self) -> u8 { 0 }\n",
                    "}\n",
                    "pub fn permute<T>(_dt: u8, _t: &Tensor) {}\n",
                    "pub fn caller(t: &Tensor) {\n",
                    "    let _x = dispatch!(permute(t.datum_type())(t));\n",
                    "}\n",
                ),
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let graph = usage_graph(
            &rust,
            UsageGraphParams {
                include_tests: true,
                paths: None,
                depth: 1,
            },
        );
        let reasons: Vec<&str> = graph
            .incomplete_reasons
            .iter()
            .map(|reason| reason.code.as_str())
            .collect();
        assert!(
            !reasons.contains(&"native_graph_failed"),
            "a capsule reference is not an invariant failure: {:?}",
            graph.incomplete_reasons
        );
        assert!(
            graph.edges.iter().any(|edge| {
                edge.from.ends_with("caller")
                    && edge.to.ends_with("permute")
                    && edge.sites.iter().any(|site| site.line == 9)
            }),
            "the macro argument must project its edge: {:?}",
            graph.edges
        );
    }

    /// A later crate stage's macro argument keeps its edge.
    ///
    /// A graph build opens one operation and runs one stage per crate, and
    /// `prepare_selected_macro_reference_overlay` answers "already done" for
    /// whatever overlay is set, so the first stage with a macro host fixes the
    /// overlay for the whole request and later stages' hosts get no capsules
    /// (lane MD, confirmed with `eprintln`s at the guard; lane IV saw all 17
    /// capsule instantiations of a 23-stage tract run in the first stage).
    ///
    /// This does not cost the edge, and that is what the fixture held. The
    /// resolution producer's own token-tree lowering enumerates a macro
    /// argument's references, plain and path-qualified alike, so neither lane
    /// MD nor lane MW could build a workspace where the missing overlay loses
    /// one; what it cost is the gap closure. Lane MW also measured what
    /// dropping the overlay per stage cost instead: tract's warm `usage_graph`
    /// failed after 17 crate stages with "cannot classify unknown preloaded
    /// endpoint", because the identities an overlay registers into the
    /// request's supplemental facts and rebaser outlived the service that can
    /// answer for them.
    ///
    /// **Both halves are fixed (lane ID-4).** The overlay is rebuilt per crate
    /// stage and dropped with the stage, and it is dropped together with
    /// everything it registered, which is what lane MW's attempt was missing.
    /// This fixture does not discriminate the fix: it passes with the overlay
    /// rebuilt per stage and without, which is the same reason lane MD and
    /// lane MW could not build a workspace where the missing overlay loses an
    /// edge. Run with the per-stage drop removed to see that. What does
    /// discriminate is
    /// `a_crate_stage_s_macro_overlay_is_dropped_with_everything_it_registered`
    /// on the mechanism, and tract's warm `usage_graph` on the symptom.
    #[test]
    fn native_rust_usage_graph_keeps_every_crate_stage_s_macro_argument_edges() {
        use crate::searchtools::{UsageGraphParams, usage_graph};

        let mut project = InlineTestProject::with_language(Language::Rust).file(
            "Cargo.toml",
            "[workspace]\nmembers = [\"alpha\", \"beta\"]\nresolver = \"2\"\n",
        );
        // Two crates alike but for their names, each with its own macro host
        // and one invocation. The macro has to live in a file of its own:
        // `lower_macro_invocation` returns early for a macro visible in the
        // invocation's own file and publishes no capsule at all.
        for name in ["alpha", "beta"] {
            project = project
                .file(
                    format!("{name}/Cargo.toml"),
                    format!(
                        "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
                    ),
                )
                .file(
                    format!("{name}/src/macros.rs"),
                    "macro_rules! pick { ($value:expr) => { $value }; }\n",
                )
                .file(
                    format!("{name}/src/lib.rs"),
                    format!(
                        concat!(
                            "#[macro_use]\n",
                            "mod macros;\n",
                            "pub fn permute_{name}(value: u8) -> u8 {{ value }}\n",
                            "pub fn caller_{name}() -> u8 {{ pick!(permute_{name}(1)) }}\n",
                        ),
                        name = name
                    ),
                );
        }
        let fixture = project.build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let graph = usage_graph(
            &rust,
            UsageGraphParams {
                include_tests: true,
                paths: None,
                depth: 1,
            },
        );
        let reasons: Vec<&str> = graph
            .incomplete_reasons
            .iter()
            .map(|reason| reason.code.as_str())
            .collect();
        assert!(
            !reasons.contains(&"native_graph_failed"),
            "the two-crate macro graph is not a request failure: {:?}",
            graph.incomplete_reasons
        );
        for name in ["alpha", "beta"] {
            assert!(
                graph.edges.iter().any(|edge| {
                    edge.from.ends_with(&format!("caller_{name}"))
                        && edge.to.ends_with(&format!("permute_{name}"))
                }),
                "crate {name}'s macro argument must project its edge, whichever \
                 stage it is: {:?}",
                graph.edges
            );
        }
    }

    /// A definition the parser published no `CodeUnit` for is out of the
    /// graph, not a failure of the whole request.
    ///
    /// `rust_impl_owner` needs a declarable path for an `impl`'s self type, so
    /// `impl DimLike for usize` mints no owner unit and its members get no
    /// `CodeUnit`. The native resolution producer still mints a definition
    /// semantic and a `source_native_declaration_bridges` row for each member,
    /// and `broadcast` is a real resolution target. The projection used to
    /// look that coordinate up in `resolution_definition_unit_crosswalks` and
    /// in the lexical-binder half of `source_declarations`, miss both, and
    /// return `Unavailable`, which the graph route turned into a store error
    /// that lost every Rust edge in the workspace.
    ///
    /// Lane CL measured it on tract at `26edc98ea`: warm `usage_graph` failed
    /// 37 s in on `data/src/dim/mod.rs`, mount 211, local key 1174, which is
    /// `fn broadcast` of `impl DimLike for usize`. 173 of tract's 72,451
    /// persisted definition semantics are in the same class.
    #[test]
    fn native_rust_usage_graph_keeps_its_edges_when_a_definition_has_no_unit() {
        use crate::searchtools::{UsageGraphParams, usage_graph};

        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"unitless\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                concat!(
                    "pub trait DimLike {\n",
                    "    fn broadcast(self, other: Self) -> Self;\n",
                    "}\n",
                    "impl DimLike for usize {\n",
                    "    fn broadcast(self, other: Self) -> Self {\n",
                    "        if self == 1 { other } else { self }\n",
                    "    }\n",
                    "}\n",
                    "pub fn helper(value: usize) -> usize {\n",
                    "    value\n",
                    "}\n",
                    "pub fn caller(a: usize, b: usize) -> usize {\n",
                    "    helper(a.broadcast(b))\n",
                    "}\n",
                ),
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let graph = usage_graph(
            &rust,
            UsageGraphParams {
                include_tests: true,
                paths: None,
                depth: 1,
            },
        );
        let reasons: Vec<&str> = graph
            .incomplete_reasons
            .iter()
            .map(|reason| reason.code.as_str())
            .collect();
        assert!(
            !reasons.contains(&"native_graph_failed"),
            "a definition with no CodeUnit is not a request failure: {:?}",
            graph.incomplete_reasons
        );
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| edge.from.ends_with("caller") && edge.to.ends_with("helper")),
            "the file's other edges must survive: {:?}",
            graph.edges
        );
        assert!(
            !graph
                .edges
                .iter()
                .any(|edge| edge.to.ends_with("broadcast")),
            "a definition with no CodeUnit is no node of the graph: {:?}",
            graph.edges
        );
    }

    /// The same for a definition a macro expansion introduces.
    ///
    /// A cross-file macro is replayed by a selected stage, which mints
    /// supplemental semantics for what the expansion declares. A staged
    /// producer publishes lexical declarations and nothing else --
    /// `resolution_capsule_declarations` takes exactly the lexical binder
    /// kinds, and a capsule has no definition-to-unit crosswalk at all -- so a
    /// generated *item* is in neither vocabulary and has no source span
    /// either: it comes from the macro's transcriber, not the invocation's own
    /// text. The projection answered `Unavailable` for it and the graph route
    /// turned that into a store error.
    ///
    /// Measured on tract at the batch-one product `83044c479`: warm
    /// `usage_graph` failed after 834 s with 62 such definitions in mount 505,
    /// `linalg/src/generic/by_scalar.rs`, where `by_scalar_impl_wrap!`
    /// generates `pub struct SMulByScalar4` and its `impl` members. The whole
    /// 13,370-node, 14,985-edge graph was lost to them.
    #[test]
    fn native_rust_usage_graph_keeps_its_edges_when_a_macro_expansion_declares_an_item() {
        use crate::searchtools::{UsageGraphParams, usage_graph};

        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"generated\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/macros.rs",
                concat!(
                    "macro_rules! kernel_impl {\n",
                    "    ($name: ident, $nr: expr) => {\n",
                    "        #[derive(Copy, Clone, Debug)]\n",
                    "        pub struct $name;\n",
                    "        impl crate::Kernel for $name {\n",
                    "            fn nr() -> usize { $nr }\n",
                    "        }\n",
                    "    };\n",
                    "}\n",
                ),
            )
            .file(
                "src/lib.rs",
                concat!(
                    "#[macro_use]\n",
                    "mod macros;\n",
                    "pub mod generic;\n",
                    "pub trait Kernel {\n",
                    "    fn nr() -> usize;\n",
                    "}\n",
                    "pub fn helper(value: usize) -> usize {\n",
                    "    value\n",
                    "}\n",
                    "pub fn caller(value: usize) -> usize {\n",
                    "    helper(value)\n",
                    "}\n",
                ),
            )
            .file("src/generic.rs", "kernel_impl!(MulByScalar4, 4);\n")
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let graph = usage_graph(
            &rust,
            UsageGraphParams {
                include_tests: true,
                paths: None,
                depth: 1,
            },
        );
        let reasons: Vec<&str> = graph
            .incomplete_reasons
            .iter()
            .map(|reason| reason.code.as_str())
            .collect();
        assert!(
            !reasons.contains(&"native_graph_failed"),
            "a definition a macro expansion declares is not a request failure: {:?}",
            graph.incomplete_reasons
        );
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| edge.from.ends_with("caller") && edge.to.ends_with("helper")),
            "the workspace's other edges must survive: {:?}",
            graph.edges
        );
    }

    /// The graph reads the items the crate declares for decided item-macro
    /// invocations (`rust_crate_macro_items`): tokio's `cfg_*` shape, a macro
    /// defined in the crate root that adds a `cfg` to each item it replays,
    /// invoked around a `mod` declaration in the root and around a function
    /// in another file. The side the profile activates is an edge target
    /// through its module path; the side it turns off has no edge, and the
    /// graph does not report the invocations as unsupported.
    #[test]
    fn native_rust_usage_graph_draws_edges_to_cfg_decorated_macro_items() {
        use crate::searchtools::{UsageGraphParams, usage_graph};

        let decorated = |name: &str, predicate: &str| {
            format!(
                "macro_rules! {name} {{\n    ($($item:item)*) => {{\n        $(\n            #[cfg({predicate})]\n            #[cfg_attr(docsrs, doc(cfg({predicate})))]\n            $item\n        )*\n    }}\n}}\n"
            )
        };
        let lib = format!(
            "{}{}{}",
            decorated("cfg_unix", "unix"),
            decorated("cfg_not_unix", "not(unix)"),
            concat!(
                "cfg_unix! { pub mod unix_side; }\n",
                "cfg_not_unix! { pub mod other_side; }\n",
                "pub mod net;\n",
                "pub fn unix_caller() -> u32 {\n",
                "    crate::unix_side::unix_only() + crate::net::unix_net()\n",
                "}\n",
                "pub fn other_caller() -> u32 {\n",
                "    crate::other_side::other_only() + crate::net::other_net()\n",
                "}\n",
            )
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"decorated\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", lib)
            .file(
                "src/unix_side.rs",
                "pub fn unix_only() -> u32 {\n    1\n}\n",
            )
            .file(
                "src/other_side.rs",
                "pub fn other_only() -> u32 {\n    2\n}\n",
            )
            .file(
                "src/net.rs",
                concat!(
                    "cfg_unix! {\n    pub fn unix_net() -> u32 {\n        3\n    }\n}\n",
                    "cfg_not_unix! {\n    pub fn other_net() -> u32 {\n        4\n    }\n}\n",
                ),
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let graph = usage_graph(
            &rust,
            UsageGraphParams {
                include_tests: true,
                paths: None,
                depth: 1,
            },
        );
        let reasons: Vec<&str> = graph
            .incomplete_reasons
            .iter()
            .map(|reason| reason.code.as_str())
            .collect();
        assert!(
            !reasons.contains(&"native_graph_failed"),
            "{:?}",
            graph.incomplete_reasons
        );
        let (caller, active, inactive) = if cfg!(unix) {
            (
                "unix_caller",
                ["unix_only", "unix_net"],
                ["other_only", "other_net"],
            )
        } else {
            (
                "other_caller",
                ["other_only", "other_net"],
                ["unix_only", "unix_net"],
            )
        };
        for target in active {
            assert!(
                graph
                    .edges
                    .iter()
                    .any(|edge| edge.from.ends_with(caller) && edge.to.ends_with(target)),
                "the active side of a decorated invocation is an edge target: {target}: {:?}",
                graph.edges
            );
        }
        for target in inactive {
            assert!(
                !graph.edges.iter().any(|edge| edge.to.ends_with(target)),
                "a decoration the profile turns off declares nothing: {target}: {:?}",
                graph.edges
            );
        }
    }

    /// An unavailable canonical fact base must reach the `usage_graph`
    /// consumer as a reported incompleteness, never as a complete graph with
    /// no edges.
    ///
    /// The preflight in `searchtools::scan_usages` used to ask only the legacy
    /// arm of a language's graph backend, so routing Rust to the native
    /// provider silently dropped `RustEdgePass::input_failure`: a workspace
    /// whose Rust facts were never published answered "complete, zero edges".
    /// That is the one shape a caller cannot tell from a real absence of
    /// references.
    #[test]
    fn native_rust_usage_graph_reports_unavailable_canonical_facts_before_scanning() {
        use crate::searchtools::{UsageGraphParams, usage_graph};

        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"preflight\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub fn target() {}\npub fn caller() { target(); }\n",
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        assert_eq!(
            rust.declarations(&file).len(),
            2,
            "the fixture publishes both declarations before its facts are removed"
        );
        let params = || UsageGraphParams {
            include_tests: true,
            paths: None,
            depth: 1,
        };

        let published = usage_graph(&rust, params());
        assert!(
            published.complete,
            "a published workspace has no input failure: {:?}",
            published.incomplete_reasons
        );
        assert_eq!(
            published.edges.len(),
            1,
            "the fixture call is one native edge: {:?}",
            published.edges
        );

        rust.analyzer_store().delete_rust_facts_for_test("rust");
        assert_eq!(
            rust.rust_files_without_facts()
                .expect("live-blob probe")
                .as_slice(),
            &[file],
            "removing the canonical witness leaves the live blob unpublished"
        );

        let unpublished = usage_graph(&rust, params());
        assert!(
            !unpublished.complete,
            "unavailable canonical Rust facts cannot report a complete graph"
        );
        let reasons: Vec<&str> = unpublished
            .incomplete_reasons
            .iter()
            .map(|reason| reason.code.as_str())
            .collect();
        assert!(
            reasons.contains(&"unavailable_canonical_facts"),
            "{:?}",
            unpublished.incomplete_reasons
        );
    }

    /// A Cargo workspace of `size` independent member crates, each one file
    /// with one intra-crate call.
    ///
    /// The members are independent so that a request naming one member's file
    /// resolves that member alone: a crate whose own member lost its facts is
    /// legitimately unavailable, and that is a different question from the
    /// preflight's.
    fn preflight_workspace(size: usize) -> crate::inline_project::BuiltInlineTestProject {
        assert!(
            size > 1,
            "the preflight fixtures compare two members or more"
        );
        let members = (0..size)
            .map(|index| format!("'part{index}'"))
            .collect::<Vec<_>>()
            .join(",");
        let mut fixture = InlineTestProject::with_language(Language::Rust).file(
            "Cargo.toml",
            format!("[workspace]\nmembers=[{members}]\nresolver='2'\n"),
        );
        for index in 0..size {
            fixture = fixture
                .file(
                    format!("part{index}/Cargo.toml"),
                    format!("[package]\nname='part{index}'\nversion='0.1.0'\nedition='2021'\n"),
                )
                .file(
                    format!("part{index}/src/lib.rs"),
                    format!(
                        "pub fn target{index}() {{}}\npub fn caller{index}() {{ target{index}(); }}\n"
                    ),
                );
        }
        fixture.build()
    }

    /// A rooted request's input authority is decided by its own files.
    ///
    /// The preflight used to enumerate every live Rust blob and ask whether
    /// each carried facts, so one unpublished `.rs` file anywhere marked the
    /// whole Rust pass unavailable and a rooted request that never named that
    /// file lost every Rust edge it asked for. It now asks about the request's
    /// own files. The unrooted request is the case where the workspace-wide
    /// answer was the honest one, and it still reports the failure, because
    /// its own file set is every analyzable file.
    ///
    /// The unpublished state is one blob's missing route witness rather than a
    /// lost fact manifest: that is the state the preflight exists for, and the
    /// only one a request can still name the file in. See
    /// `AnalyzerStore::drop_rust_route_witness_for_blob_for_test`.
    #[test]
    fn rooted_usage_graph_is_unavailable_only_for_its_own_unpublished_files() {
        use crate::searchtools::{UsageGraphParams, usage_graph};

        let fixture = preflight_workspace(2);
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let kept = fixture.file("part0/src/lib.rs");
        let dropped = fixture.file("part1/src/lib.rs");
        assert_eq!(rust.declarations(&kept).len(), 2);
        assert_eq!(rust.declarations(&dropped).len(), 2);

        let dropped_oid = rust
            .live_path_snapshot()
            .oid_for_path(&dropped)
            .expect("the unpublished file has a live blob identity");
        rust.analyzer_store()
            .drop_rust_route_witness_for_blob_for_test("rust", dropped_oid);
        assert_eq!(
            rust.rust_files_without_facts()
                .expect("live-blob probe")
                .as_slice(),
            std::slice::from_ref(&dropped),
            "exactly one live blob lost its route witness"
        );

        let analyzed: Vec<ProjectFile> = rust.get_analyzed_files().into_iter().collect();
        assert!(
            analyzed.contains(&dropped),
            "the unpublished file is still an analyzed file, so a request can name it: {analyzed:?}"
        );
        // The unrooted request's file set, materialized the way production
        // materializes it.
        let analyzable: Vec<ProjectFile> = rust
            .source_file_inventory()
            .rows
            .into_iter()
            .filter(|file| crate::analyzer::common::language_for_file(file) == Language::Rust)
            .collect();
        let provider = RustNativeWorkspaceGraphProvider;
        assert!(
            provider
                .input_failure(&rust, std::slice::from_ref(&kept))
                .is_none(),
            "a request naming only the published file has no input failure"
        );
        assert_eq!(
            provider
                .input_failure(&rust, &analyzable)
                .expect("every analyzable file includes the unpublished one")
                .files
                .as_slice(),
            std::slice::from_ref(&dropped),
            "the failure names the unpublished file"
        );

        let rooted = usage_graph(
            &rust,
            UsageGraphParams {
                include_tests: true,
                paths: Some(vec!["part0/src/lib.rs".to_string()]),
                depth: 1,
            },
        );
        assert!(
            rooted.complete,
            "a rooted request must not be failed by a file it never named: {:?}",
            rooted.incomplete_reasons
        );
        assert_eq!(
            rooted.edges.len(),
            1,
            "the named file's own call is still an edge: {:?}",
            rooted.edges
        );

        let unrooted = usage_graph(
            &rust,
            UsageGraphParams {
                include_tests: true,
                paths: None,
                depth: 1,
            },
        );
        assert!(
            !unrooted.complete
                && unrooted.incomplete_reasons.iter().any(|reason| {
                    reason.code == "unavailable_canonical_facts"
                        && reason
                            .message
                            .contains("canonical Rust facts are unavailable for live files")
                }),
            "an unrooted request resolves every analyzable file, so its preflight reports the \
             failure: {:?}",
            unrooted.incomplete_reasons
        );
    }

    /// Statements and decoded rows a traced reader saw between registration
    /// and unregistration.
    ///
    /// The technique is `point_latency.rs`'s: register a SQLite
    /// `SQLITE_TRACE_STMT | SQLITE_TRACE_ROW` callback on a pooled reader,
    /// return the reader to the pool so the production read checks the same
    /// connection back out, then reacquire it to unregister. The pool hands
    /// back its most recently returned idle reader, and these fixtures are
    /// single threaded, so the traced connection is the one the probe uses.
    #[cfg(test)]
    #[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
    struct TracedSqlCost {
        statements: usize,
        rows: usize,
    }

    thread_local! {
        static TRACED_SQL_COST: std::cell::Cell<TracedSqlCost> =
            const { std::cell::Cell::new(TracedSqlCost { statements: 0, rows: 0 }) };
    }

    unsafe extern "C" fn record_traced_sql(
        event: std::ffi::c_uint,
        _context: *mut std::ffi::c_void,
        _statement: *mut std::ffi::c_void,
        _raw_sql: *mut std::ffi::c_void,
    ) -> std::ffi::c_int {
        TRACED_SQL_COST.with(|cost| {
            let mut current = cost.get();
            match event {
                rusqlite::ffi::SQLITE_TRACE_STMT => current.statements += 1,
                rusqlite::ffi::SQLITE_TRACE_ROW => current.rows += 1,
                _ => unreachable!("only statement and row events are registered"),
            }
            cost.set(current);
        });
        0
    }

    /// Run `probe` with the store's next pooled reader traced, and return what
    /// that reader executed.
    fn traced_store_sql(
        store: &crate::analyzer::store::AnalyzerStore,
        probe: impl FnOnce(),
    ) -> TracedSqlCost {
        {
            let connection = store.read_conn().expect("check out a reader to trace");
            // SAFETY: the callback keeps no SQLite pointers, and the same
            // reader is checked out again below to unregister it before the
            // store is dropped.
            let status = unsafe {
                rusqlite::ffi::sqlite3_trace_v2(
                    connection.handle(),
                    rusqlite::ffi::SQLITE_TRACE_STMT | rusqlite::ffi::SQLITE_TRACE_ROW,
                    Some(record_traced_sql),
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(status, rusqlite::ffi::SQLITE_OK);
        }
        TRACED_SQL_COST.with(|cost| cost.set(TracedSqlCost::default()));
        probe();
        let cost = TRACED_SQL_COST.with(Cell::get);
        let connection = store.read_conn().expect("check out the traced reader");
        // SAFETY: a zero mask removes the callback from the same connection.
        let status = unsafe {
            rusqlite::ffi::sqlite3_trace_v2(connection.handle(), 0, None, std::ptr::null_mut())
        };
        assert_eq!(status, rusqlite::ffi::SQLITE_OK);
        cost
    }

    /// A rooted request's preflight costs what the request names, not what the
    /// workspace holds.
    ///
    /// The old preflight read every live Rust blob's publication witness on
    /// every `usage_graph` request, so its statement and row counts grew with
    /// the workspace. The oracle is two workspaces of the same per-file shape
    /// and different sizes: the same one-file rooted preflight must execute
    /// the same statements and decode the same rows in both. The unrooted
    /// preflight of the larger workspace is measured beside it so the pin
    /// cannot pass by measuring nothing -- it is the shape whose cost is
    /// expected to grow.
    #[test]
    fn rooted_preflight_sql_does_not_grow_with_the_workspace() {
        let mut rooted = Vec::new();
        let mut unrooted = Vec::new();
        for size in [2usize, 24] {
            let fixture = preflight_workspace(size);
            let rust = RustAnalyzer::new(fixture.project_dyn());
            // The unrooted shape's file set is the analyzable inventory, which
            // is what production passes; here every member is published, so it
            // is the member sources and nothing else.
            let analyzable: Vec<ProjectFile> = rust
                .source_file_inventory()
                .rows
                .into_iter()
                .filter(|file| crate::analyzer::common::language_for_file(file) == Language::Rust)
                .collect();
            assert_eq!(
                analyzable.len(),
                size,
                "the fixture has one Rust source file per member crate"
            );
            let named = vec![fixture.file("part0/src/lib.rs")];
            let provider = RustNativeWorkspaceGraphProvider;
            // Warm the snapshot and the reader's prepared statements first, so
            // what is measured is the steady-state cost of one more preflight.
            assert!(provider.input_failure(&rust, &named).is_none());
            assert!(provider.input_failure(&rust, &analyzable).is_none());
            let store = rust.analyzer_store();
            rooted.push((
                size,
                traced_store_sql(store, || {
                    assert!(provider.input_failure(&rust, &named).is_none());
                }),
            ));
            unrooted.push((
                size,
                traced_store_sql(store, || {
                    assert!(provider.input_failure(&rust, &analyzable).is_none());
                }),
            ));
        }
        eprintln!("preflight SQL (files, rooted, unrooted): {rooted:?} {unrooted:?}");
        assert_eq!(
            rooted[0].1, rooted[1].1,
            "a one-file rooted preflight must cost the same at both workspace sizes: {rooted:?}"
        );
        assert!(
            unrooted[0].1.rows < unrooted[1].1.rows,
            "the unrooted preflight reads every analyzable file, so its rows must grow: {unrooted:?}"
        );
    }

    fn graph(
        outcome: RustNativeWorkspaceGraphOutcome,
    ) -> (bool, SelectedWorkspaceUsageGraphProjection) {
        match outcome {
            RustNativeWorkspaceGraphOutcome::Complete(graph) => (true, graph),
            RustNativeWorkspaceGraphOutcome::Incomplete(graph) => (false, graph),
            RustNativeWorkspaceGraphOutcome::Cancelled => panic!("unexpected cancellation"),
            RustNativeWorkspaceGraphOutcome::Stale(reason) => panic!("unexpected stale: {reason}"),
            RustNativeWorkspaceGraphOutcome::Unavailable(reason) => {
                panic!("unexpected unavailable: {reason}")
            }
        }
    }

    #[test]
    fn native_point_reverse_and_rooted_graph_agree_across_renamed_mounted_targets() {
        use crate::analyzer::Range;
        use crate::analyzer::languages::BoundedReceiverQuery;
        use crate::analyzer::rust::native_points::resolve_rust_definition_bounded;
        use crate::analyzer::rust::native_usages::find_native_usages;
        use crate::analyzer::usages::get_definition::{
            BoundedResolution, DefinitionLookupStatus, ResolvedReferenceSite,
        };
        use crate::analyzer::usages::outcome::GraphUsageOutcome;
        use crate::analyzer::usages::{FuzzyResult, UsageProof};
        use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
        use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;

        let first = "use crate::left::target as chosen;\npub fn caller() { chosen(); }\n";
        // The token tree must stay unenumerable: since the producer reads the
        // arguments of a definition-less macro as expressions, only a group it
        // cannot lower -- here a module mount, which belongs to declaration
        // replay -- still leaves the reference inventory incomplete.
        let second = "use crate::right::target as chosen;\npub fn caller() { chosen(); }\npub fn opaque() { unknown_macro! { mod generated; } }\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"identity_law\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub mod left; pub mod right; pub mod first; pub mod second;\n",
            )
            .file("src/left.rs", "pub fn target() {}\n")
            .file("src/right.rs", "pub fn target() {}\n")
            .file("src/first.rs", first)
            .file("src/second.rs", second)
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let targets = ["src/left.rs", "src/right.rs"].map(|path| {
            rust.declarations(&fixture.file(path))
                .into_iter()
                .find(|unit| unit.identifier() == "target")
                .expect("fixture target")
        });
        assert_ne!(
            targets[0].declaration_id(),
            targets[1].declaration_id(),
            "identical source bytes at different mounts name distinct declarations"
        );
        let cancellation = CancellationToken::new();
        for (index, path, source, expected_complete) in [
            (0, "src/first.rs", first, true),
            (1, "src/second.rs", second, false),
        ] {
            let file = fixture.file(path);
            let caller = rust
                .declarations(&file)
                .into_iter()
                .find(|unit| unit.identifier() == "caller")
                .expect("fixture caller");
            let expected_target = targets[index].declaration_id();
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(source, None).unwrap();
            let mut pending = vec![tree.root_node()];
            let mut calls = Vec::new();
            while let Some(node) = pending.pop() {
                if node.kind() == "call_expression" {
                    calls.push(node.child_by_field_name("function").unwrap());
                }
                pending.extend(node.named_children(&mut node.walk()));
            }
            assert_eq!(calls.len(), 1);
            let call = calls[0];
            let site = ResolvedReferenceSite {
                path: path.to_owned(),
                text: call.utf8_text(source.as_bytes()).unwrap().to_owned(),
                range: Range {
                    start_byte: call.start_byte(),
                    end_byte: call.end_byte(),
                    start_line: call.start_position().row,
                    end_line: call.end_position().row,
                },
                focus_start_byte: call.start_byte(),
                focus_end_byte: call.end_byte(),
            };
            let BoundedResolution::Complete { value: point, .. } =
                resolve_rust_definition_bounded(BoundedReceiverQuery {
                    analyzer: &rust,
                    file: &file,
                    source,
                    tree: Some(&tree),
                    site: &site,
                    budget: ReceiverAnalysisBudget::default(),
                    cancellation: Some(&cancellation),
                })
            else {
                panic!("native point must finish");
            };
            assert_eq!(point.status, DefinitionLookupStatus::Resolved, "{point:?}");
            assert_eq!(
                point
                    .definitions
                    .iter()
                    .map(|unit| unit.declaration_id())
                    .collect::<Vec<_>>(),
                vec![expected_target.clone()]
            );

            let admitted = HashSet::from_iter([file.clone()]);
            let reverse = find_native_usages(&rust, &targets, &UsageScanScope::new(&admitted), 10);
            let GraphUsageOutcome::Resolved(reverse) = reverse else {
                panic!("native reverse must publish semantic evidence: {reverse:?}");
            };
            assert_eq!(
                matches!(&reverse, FuzzyResult::Success { .. }),
                expected_complete,
                "{reverse:?}"
            );
            let buckets = match &reverse {
                FuzzyResult::Success {
                    hits_by_overload, ..
                }
                | FuzzyResult::Incomplete {
                    hits_by_overload, ..
                } => hits_by_overload,
                _ => panic!("unexpected reverse terminal: {reverse:?}"),
            };
            let positive_targets = buckets
                .iter()
                .filter(|(_, hits)| !hits.is_empty())
                .map(|(target, _)| target.declaration_id())
                .collect::<HashSet<_>>();
            assert_eq!(
                positive_targets,
                HashSet::from_iter([expected_target.clone()])
            );
            let hits = reverse.all_hits();
            assert_eq!(hits.len(), 1, "{reverse:?}");
            assert!(
                hits.iter()
                    .all(|hit| hit.file == file && hit.proof == UsageProof::Proven)
            );

            let (complete, rooted) = graph(
                build_rust_native_workspace_graph_for_files(
                    &rust,
                    std::slice::from_ref(&file),
                    1,
                    &cancellation,
                )
                .unwrap(),
            );
            assert_eq!(
                complete, expected_complete,
                "{:?}",
                rooted.forward_completeness
            );
            assert_eq!(rooted.edges.len(), 1);
            let edge = &rooted.edges[0];
            assert_eq!(
                rooted.nodes[edge.from].primary.declaration_id(),
                caller.declaration_id()
            );
            assert_eq!(
                rooted.nodes[edge.to].primary.declaration_id(),
                expected_target
            );
            assert_ne!(
                rooted.nodes[edge.to].primary.source(),
                &file,
                "admitting callers must retain the foreign target endpoint"
            );
            assert_eq!(edge.counts.calls, 1);
            assert!(edge.sites.iter().all(|(source, _)| source == &file));
            assert_eq!(rooted.nodes[edge.to].unproven_inbound, 0);
        }
    }

    #[test]
    fn rooted_native_graph_admits_callers_before_source_projection() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"rooted_graph\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub mod api; pub mod caller; pub mod unrelated;\n",
            )
            .file(
                "src/api.rs",
                "pub fn target() {}\npub fn unused_dependency() {}\n",
            )
            .file(
                "src/caller.rs",
                "pub fn caller() { crate::api::target(); }\npub fn unused_root() {}\n",
            )
            .file(
                "src/unrelated.rs",
                "pub fn other() { crate::api::target(); }\ninclude!(\"generated.rs\");\n",
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        rust.test_hooks()
            .reset_full_declaration_scan_count_for_test();
        let rooted = match RustNativeWorkspaceGraphProvider
            .project(
                &rust,
                &[fixture.file("src/caller.rs")],
                &CancellationToken::new(),
            )
            .unwrap()
        {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph) => graph,
            _ => panic!("unrelated source inventory must not weaken rooted coverage"),
        };
        assert_eq!(rooted.edges.len(), 1);
        let edge = &rooted.edges[0];
        assert_eq!(
            rooted.nodes[edge.from].primary.source(),
            &fixture.file("src/caller.rs")
        );
        assert_eq!(
            rooted.nodes[edge.to].primary.source(),
            &fixture.file("src/api.rs")
        );
        assert_eq!(rooted.nodes[edge.to].primary.terminal_name(), "target");
        assert!(
            rooted
                .nodes
                .iter()
                .any(|node| node.primary.terminal_name() == "unused_root")
        );
        assert!(
            !rooted
                .nodes
                .iter()
                .any(|node| node.primary.terminal_name() == "unused_dependency"
                    || node.primary.source() == &fixture.file("src/unrelated.rs"))
        );
        assert_eq!(rust.test_hooks().full_declaration_scan_count_for_test(), 0);
        let empty = match RustNativeWorkspaceGraphProvider
            .project(&rust, &[], &CancellationToken::new())
            .unwrap()
        {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph) => graph,
            _ => panic!("an empty admitted scope must produce a complete empty graph"),
        };
        assert!(empty.nodes.is_empty() && empty.edges.is_empty());
        assert_eq!(empty.reference_count, 0);
        let (full_complete, full) = graph(
            build_rust_native_workspace_graph_for_files(
                &rust,
                &[
                    fixture.file("src/lib.rs"),
                    fixture.file("src/api.rs"),
                    fixture.file("src/caller.rs"),
                    fixture.file("src/unrelated.rs"),
                ],
                1,
                &CancellationToken::new(),
            )
            .unwrap(),
        );
        assert!(!full_complete);
        assert!(rooted.reference_count < full.reference_count);
    }

    #[test]
    fn rooted_native_graph_preserves_dependency_resolution_uncertainty() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"rooted_dependency_gap\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .file("src/lib.rs", "pub mod api;\npub fn caller() { api::generated(); }\n")
            .file("src/api.rs", "include!(\"generated.rs\");\n")
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let (complete, rooted) = graph(
            build_rust_native_workspace_graph_for_files(
                &rust,
                &[fixture.file("src/lib.rs")],
                1,
                &CancellationToken::new(),
            )
            .unwrap(),
        );
        assert!(
            !complete,
            "source admission must not close uncertain dependency bindings: {:?}",
            rooted.forward_completeness
        );
        assert!(rooted.edges.is_empty());
    }

    #[test]
    fn rooted_native_graph_retains_overlay_gaps_and_discards_late_cancelled_rows() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"rooted_overlay\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub mod api; pub mod caller;\n")
            .file("src/api.rs", "pub fn target() {}\n")
            .file("src/caller.rs", "pub fn caller() {}\n")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let overlay = std::sync::Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(
            fixture.file("src/caller.rs").abs_path(),
            "pub fn caller() { crate::api::target(); }\ninclude!(\"generated.rs\");\n".to_string()
        ));
        let rust = disk.clone_with_project(std::sync::Arc::new(overlay.snapshot()));
        assert!(!rust.declarations(&fixture.file("src/caller.rs")).is_empty());
        let files = [fixture.file("src/caller.rs")];
        let (complete, rooted) = graph(
            build_rust_native_workspace_graph_for_files(
                &rust,
                &files,
                1,
                &CancellationToken::new(),
            )
            .unwrap(),
        );
        assert!(!complete);
        assert_eq!(rooted.edges.len(), 1);
        assert_eq!(
            rooted.nodes[rooted.edges[0].to].primary.terminal_name(),
            "target"
        );
        let cancellation = CancellationToken::new();
        let mut batches = 0;
        let cancelled = build_rust_native_workspace_graph_with_progress(
            &rust,
            &files,
            1,
            &cancellation,
            &mut || {
                batches += 1;
                cancellation.cancel();
            },
        )
        .unwrap();
        assert_eq!(batches, 1);
        assert!(matches!(
            cancelled,
            RustNativeWorkspaceGraphOutcome::Cancelled
        ));
        assert!(matches!(
            build_rust_native_workspace_graph_for_files(&rust, &files, 1, &cancellation).unwrap(),
            RustNativeWorkspaceGraphOutcome::Cancelled
        ));
    }

    #[test]
    fn native_rust_graph_retains_turbofish_value_references() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname='generic_values'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file(
                "src/lib.rs",
                concat!(
                    "pub struct Unit<const N: usize>;\n",
                    "pub fn identity<T>() {}\n",
                    "pub fn caller() { let _unit = Unit::<4>; let _function = identity::<u8>; }\n",
                ),
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let (_, graph) = graph(
            build_rust_native_workspace_graph_for_files(
                &rust,
                &[fixture.file("src/lib.rs")],
                2,
                &CancellationToken::new(),
            )
            .unwrap(),
        );
        let mut targets = graph
            .edges
            .iter()
            .filter(|edge| graph.nodes[edge.from].primary.terminal_name() == "caller")
            .map(|edge| {
                (
                    graph.nodes[edge.to].primary.terminal_name().to_owned(),
                    edge.counts.calls,
                )
            })
            .collect::<Vec<_>>();
        targets.sort();
        assert_eq!(
            targets,
            [("Unit".to_owned(), 0), ("identity".to_owned(), 0)],
            "generic values retain dependencies without inventing calls"
        );
    }

    #[test]
    fn native_rust_graph_retains_impl_method_generic_bounds() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname='method_bounds'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file(
                "src/lib.rs",
                concat!(
                    "pub trait First {}\n",
                    "pub trait Second {}\n",
                    "pub struct Item;\n",
                    "impl Item { pub fn target<T: First, U>() where U: Second {} }\n",
                ),
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let (_, graph) = graph(
            build_rust_native_workspace_graph_for_files(
                &rust,
                &[fixture.file("src/lib.rs")],
                2,
                &CancellationToken::new(),
            )
            .unwrap(),
        );
        let mut targets = graph
            .edges
            .iter()
            .filter(|edge| graph.nodes[edge.from].primary.terminal_name() == "target")
            .map(|edge| graph.nodes[edge.to].primary.terminal_name().to_owned())
            .collect::<Vec<_>>();
        targets.sort();
        assert_eq!(
            targets,
            ["First", "Second"],
            "both inline and where-clause dependencies belong to the method"
        );
    }

    #[test]
    fn native_rust_graph_retains_same_module_function_value_reference() {
        use crate::analyzer::rust::native_usages::find_native_usages;
        use crate::analyzer::usages::outcome::GraphUsageOutcome;
        use crate::analyzer::usages::{UsageHitKind, UsageProof};
        use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;

        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"native_graph\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .file("src/lib.rs", "pub fn target() {}\npub fn accept(callback: fn()) {}\npub fn caller() { accept(target); }\n")
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let (_, graph) = graph(
            build_rust_native_workspace_graph_for_files(
                &rust,
                &[fixture.file("src/lib.rs")],
                2,
                &CancellationToken::new(),
            )
            .unwrap(),
        );
        assert!(
            graph.edges.iter().any(|edge| {
                graph.nodes[edge.from].primary.terminal_name() == "caller"
                    && graph.nodes[edge.to].primary.terminal_name() == "target"
            }),
            "passing a module function as a value must retain its reference edge"
        );
        let target = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "target")
            .expect("fixture function");
        let admitted = HashSet::from_iter([fixture.file("src/lib.rs")]);
        let reverse = find_native_usages(&rust, &[target], &UsageScanScope::new(&admitted), 10);
        let GraphUsageOutcome::Resolved(reverse) = reverse else {
            panic!("native reverse must publish semantic evidence: {reverse:?}");
        };
        let hits = reverse.all_hits();
        assert_eq!(hits.len(), 1, "{reverse:?}");
        let hit = hits.iter().next().expect("one reference was checked above");
        assert_eq!(hit.kind, UsageHitKind::Reference);
        assert_eq!(hit.proof, UsageProof::Proven);
    }

    #[test]
    fn native_rust_graph_retains_exact_endpoints_and_distinct_line_weights() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"native_graph\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .file("src/lib.rs", "pub mod dep;\nuse dep::target;\npub fn caller() { target(); target();\n target(); }\npub fn second() { target(); }\npub fn unused() {}\n")
            .file("src/dep.rs", "pub fn target() {}\n")
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let (complete, graph) = graph(
            build_rust_native_workspace_graph_for_files(
                &rust,
                &[fixture.file("src/lib.rs"), fixture.file("src/dep.rs")],
                2,
                &CancellationToken::new(),
            )
            .unwrap(),
        );
        assert!(
            complete,
            "native source inventory must certify this closed fixture: {:?}",
            graph.forward_completeness
        );
        let mut edges = graph
            .edges
            .iter()
            .map(|edge| {
                let caller = &graph.nodes[edge.from].primary;
                let target = &graph.nodes[edge.to].primary;
                assert_eq!(caller.source(), &fixture.file("src/lib.rs"));
                assert_eq!(target.source(), &fixture.file("src/dep.rs"));
                assert_eq!(target.terminal_name(), "target");
                assert_eq!(edge.counts.total(), usize::from(edge.counts.calls));
                (
                    caller.terminal_name().to_string(),
                    edge.counts.calls,
                    edge.sites.iter().map(|(_, line)| *line).collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        edges.sort();
        assert_eq!(
            edges,
            vec![
                ("caller".into(), 2, vec![3, 4]),
                ("second".into(), 1, vec![5])
            ]
        );
        assert!(
            graph
                .nodes
                .iter()
                .any(|node| node.primary.terminal_name() == "unused"),
            "unused native declarations remain candidates for dead-code consumers"
        );
        assert!(
            graph
                .nodes
                .iter()
                .all(|node| node.unproven_inbound == 0 && node.truncated_inbound.is_none())
        );
        assert!(graph.batch_count > 1);
    }

    #[test]
    fn native_rust_graph_reports_block_local_reference_owner_without_refusing() {
        use crate::analyzer::structural::edges::EdgeAxis;

        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"local_owner\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                concat!(
                    "pub fn target() {}\n",
                    "pub fn outer() {\n",
                    "    fn nested() { target(); }\n",
                    "    nested();\n",
                    "}\n",
                    "pub fn sibling() { target(); }\n",
                ),
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let (complete, graph) = graph(
            build_rust_native_workspace_graph_for_files(
                &rust,
                &[fixture.file("src/lib.rs")],
                2,
                &CancellationToken::new(),
            )
            .unwrap(),
        );
        assert!(!complete, "the local callable has no graph CodeUnit");
        assert!(
            !graph
                .forward_completeness
                .covers(EdgeAxis::OwnerClassification),
            "the omitted local owner must remain explicit: {:?}",
            graph.forward_completeness
        );
        let edges = graph
            .edges
            .iter()
            .map(|edge| {
                (
                    graph.nodes[edge.from].primary.terminal_name(),
                    graph.nodes[edge.to].primary.terminal_name(),
                    edge.counts.calls,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(edges, vec![("sibling", "target", 1)]);
    }

    #[test]
    fn native_rust_graph_reports_block_local_type_reference_owner_without_refusing() {
        use crate::analyzer::structural::edges::EdgeAxis;

        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"local_type_owner\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                concat!(
                    "pub struct TDim;\n",
                    "pub fn target() {}\n",
                    "pub fn outer() {\n",
                    "    fn scan_model() { let _: Option<TDim> = None; }\n",
                    "    scan_model();\n",
                    "}\n",
                    "pub fn sibling() { target(); }\n",
                ),
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let (complete, graph) = graph(
            build_rust_native_workspace_graph_for_files(
                &rust,
                &[fixture.file("src/lib.rs")],
                2,
                &CancellationToken::new(),
            )
            .unwrap(),
        );
        assert!(!complete);
        assert!(
            !graph
                .forward_completeness
                .covers(EdgeAxis::OwnerClassification),
            "the nested type reference must report its lexical owner: {:?}",
            graph.forward_completeness
        );
        let edges = graph
            .edges
            .iter()
            .map(|edge| {
                (
                    graph.nodes[edge.from].primary.terminal_name(),
                    graph.nodes[edge.to].primary.terminal_name(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(edges, vec![("sibling", "target")]);
    }

    #[test]
    fn native_rust_graph_projects_block_local_struct_fields_without_refusing() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"local_field\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                concat!(
                    "pub fn target() {}\n",
                    "pub fn outer() {\n",
                    "    struct Local { value: i32 }\n",
                    "    let local: Local = Local { value: 0 };\n",
                    "    let _ = local.value;\n",
                    "}\n",
                    "pub fn sibling() { target(); }\n",
                ),
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let (complete, graph) = graph(
            build_rust_native_workspace_graph_for_files(
                &rust,
                &[fixture.file("src/lib.rs")],
                2,
                &CancellationToken::new(),
            )
            .unwrap(),
        );
        assert!(!complete, "the local type remains outside the graph domain");
        let edges = graph
            .edges
            .iter()
            .map(|edge| {
                (
                    graph.nodes[edge.from].primary.terminal_name(),
                    graph.nodes[edge.to].primary.terminal_name(),
                    edge.counts.calls,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(edges, vec![("sibling", "target", 1)]);
    }

    #[test]
    fn native_rust_graph_keeps_positive_edges_with_incomplete_source_inventory() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"native_graph_gap\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub fn target() {}\npub fn caller() { target(); }\ninclude!(\"generated.rs\");\n",
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let (complete, graph) = graph(
            build_rust_native_workspace_graph_for_files(
                &rust,
                &[fixture.file("src/lib.rs")],
                2,
                &CancellationToken::new(),
            )
            .unwrap(),
        );
        assert!(
            !complete,
            "an unexpanded include cannot certify absent graph edges"
        );
        assert_eq!(graph.edges.len(), 1);
        assert_eq!(
            graph.nodes[graph.edges[0].from].primary.terminal_name(),
            "caller"
        );
        assert_eq!(
            graph.nodes[graph.edges[0].to].primary.terminal_name(),
            "target"
        );
        assert_eq!(graph.edges[0].counts.calls, 1);
        assert!(matches!(
            graph.forward_completeness,
            EdgeCompleteness::Incomplete { .. }
        ));
    }

    // `native_rust_graph_cancelled_operation_publishes_no_graph` and
    // `native_rust_graph_late_cancellation_discards_staged_edges` used to pin
    // immediate and mid-staging cancellation through the root-less builder.
    // `rooted_native_graph_retains_overlay_gaps_and_discards_late_cancelled_rows`
    // above already asserts both shapes through the rooted API alone: it
    // stages one batch, cancels from the progress callback, asserts
    // `batches == 1` and `Cancelled`, then calls the rooted builder again with
    // the same already-cancelled token and asserts `Cancelled`. Deleted rather
    // than restated; a root-less restatement would have duplicated that pin.

    /// A workspace graph holds one crate's context at a time.
    ///
    /// The build used to compile one context over every selected crate and
    /// hold it from the first unit to the last, so what it retained while it
    /// resolved was the workspace's bridge inventory. Two workspaces of the
    /// same per-crate shape, one with two crates and one with eight, pin that:
    /// the largest context either build compiles is one crate's, and it does
    /// not grow with the crate count. The edge counts in the same measurement
    /// are the independent half of the oracle -- a build that resolved fewer
    /// crates would also carry a smaller context.
    #[test]
    fn workspace_graph_context_is_bounded_by_one_crate() {
        use crate::analyzer::store::resolution_operation::{
            reset_rust_context_bridge_peak_for_test, rust_context_bridge_peak_for_test,
        };
        let measurements = [2usize, 8].map(|crates| {
            let consumers = crates - 1;
            let members = (0..consumers)
                .map(|index| format!("'consumer{index}'"))
                .chain(std::iter::once("'provider'".to_owned()))
                .collect::<Vec<_>>()
                .join(",");
            let mut builder = InlineTestProject::with_language(Language::Rust)
                .file(
                    "Cargo.toml",
                    format!("[workspace]\nmembers=[{members}]\nresolver='2'\n"),
                )
                .file(
                    "provider/Cargo.toml",
                    "[package]\nname='provider'\nversion='0.1.0'\nedition='2021'\n",
                )
                .file(
                    "provider/src/lib.rs",
                    "pub fn target() {}\npub fn provider_caller() { target(); }\n",
                );
            for index in 0..consumers {
                builder = builder
                    .file(
                        format!("consumer{index}/Cargo.toml"),
                        format!(
                            "[package]\nname='consumer{index}'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nprovider={{path='../provider'}}\n"
                        ),
                    )
                    .file(
                        format!("consumer{index}/src/lib.rs"),
                        "use provider::target;\npub fn caller() { target(); }\n",
                    );
            }
            let fixture = builder.build();
            let rust = RustAnalyzer::new(fixture.project_dyn());
            let mut root_files = vec![fixture.file("provider/src/lib.rs")];
            root_files.extend(
                (0..consumers).map(|index| fixture.file(format!("consumer{index}/src/lib.rs"))),
            );
            reset_rust_context_bridge_peak_for_test();
            let outcome = build_rust_native_workspace_graph_for_files(
                &rust,
                &root_files,
                8,
                &CancellationToken::new(),
            )
            .expect("native workspace graph");
            let (RustNativeWorkspaceGraphOutcome::Complete(graph)
            | RustNativeWorkspaceGraphOutcome::Incomplete(graph)) = outcome
            else {
                panic!("the fixture workspace projects a graph");
            };
            (crates, rust_context_bridge_peak_for_test(), graph.edges.len())
        });
        eprintln!(
            "workspace graph context (crates, peak context bridges, edges): {measurements:?}"
        );
        assert_eq!(
            measurements[1].1, measurements[0].1,
            "the largest context a workspace graph compiles is one crate's: {measurements:?}"
        );
        for (crates, _, edges) in measurements {
            assert_eq!(
                edges, crates,
                "every crate contributes its own call edge: {measurements:?}"
            );
        }
    }

    /// Staging a leaf crate produces no interior in a crate that depends on it.
    ///
    /// A reference written in crate A binds to a declaration in A or in A's
    /// transitive dependency closure. Nothing in a crate that depends on A can
    /// answer it, so opening those blobs is pure cost, and on tract it was
    /// nearly all of the cost: lane ER attributed 1,758 of batch 0's 1,836
    /// interior productions, 95.8 percent, to crates that depend on the staged
    /// `tract-data`, which has no workspace dependency at all.
    ///
    /// The fixture is that shape in miniature. `provider` is the leaf; every
    /// consumer depends on it, imports the same name and declares its own
    /// member under the same spelling, so a membership read keyed on either
    /// name names every consumer blob. Staging the provider's file alone at one
    /// and at twenty dependents, the productions must be the same number: the
    /// count is bounded by the closure, which is the provider itself, and not
    /// by how many crates use it. Require the expected provider edge as well
    /// as equal answers so an empty graph cannot satisfy the oracle.
    #[test]
    fn staging_a_leaf_crate_keeps_edges_independent_of_its_dependents() {
        let measurements = [1usize, 20].map(|dependents| {
            let members = (0..dependents)
                .map(|index| format!("'consumer{index}'"))
                .chain(std::iter::once("'provider'".to_owned()))
                .collect::<Vec<_>>()
                .join(",");
            let mut builder = InlineTestProject::with_language(Language::Rust)
                .file(
                    "Cargo.toml",
                    format!("[workspace]\nmembers=[{members}]\nresolver='2'\n"),
                )
                .file(
                    "provider/Cargo.toml",
                    "[package]\nname='provider'\nversion='0.1.0'\nedition='2021'\n",
                )
                .file(
                    "provider/src/lib.rs",
                    concat!(
                        "pub struct Unit;\n",
                        "impl Unit {\n",
                        "    pub fn shared_member(&self) -> u8 { 0 }\n",
                        "}\n",
                        "pub fn target() {}\n",
                        "pub fn provider_caller(unit: &Unit) -> u8 {\n",
                        "    target();\n",
                        "    unit.shared_member()\n",
                        "}\n",
                    ),
                );
            for index in 0..dependents {
                builder = builder
                    .file(
                        format!("consumer{index}/Cargo.toml"),
                        format!(
                            "[package]\nname='consumer{index}'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nprovider={{path='../provider'}}\n"
                        ),
                    )
                    .file(
                        format!("consumer{index}/src/lib.rs"),
                        concat!(
                            "use provider::target;\n",
                            "pub struct Local;\n",
                            "impl Local {\n",
                            "    pub fn shared_member(&self) -> u8 { 1 }\n",
                            "}\n",
                            "pub fn caller(local: &Local) -> u8 {\n",
                            "    target();\n",
                            "    local.shared_member()\n",
                            "}\n",
                        ),
                    );
            }
            let fixture = builder.build();
            let rust = RustAnalyzer::new(fixture.project_dyn());
            let outcome = build_rust_native_workspace_graph_for_files(
                &rust,
                &[fixture.file("provider/src/lib.rs")],
                8,
                &CancellationToken::new(),
            )
            .expect("native workspace graph");
            let (RustNativeWorkspaceGraphOutcome::Complete(graph)
            | RustNativeWorkspaceGraphOutcome::Incomplete(graph)) = outcome
            else {
                panic!("the fixture workspace projects a graph");
            };
            let edges = graph
                .edges
                .iter()
                .map(|edge| {
                    (
                        graph.nodes[edge.from].primary.terminal_name().to_owned(),
                        graph.nodes[edge.to].primary.terminal_name().to_owned(),
                    )
                })
                .collect::<Vec<_>>();
            (dependents, edges)
        });
        eprintln!("leaf crate staging (dependents, edges): {measurements:?}");
        assert_eq!(
            measurements[0].1, measurements[1].1,
            "the provider's own edges do not depend on how many crates use it: \
             {measurements:?}"
        );
        assert!(
            measurements[0]
                .1
                .contains(&("provider_caller".to_owned(), "target".to_owned())),
            "the staged crate's own call must still be resolved: {measurements:?}"
        );
    }

    /// Narrowing the scope never turns an `Incomplete` into a `Complete`.
    ///
    /// The candidate gap boxes are read from `resolution_candidate_gap_headers`
    /// over the request's scope, so a gap in a blob the request cannot bind
    /// into stops qualifying its answer. That is the correction, not a loss: a
    /// gap in a crate that depends on the staged one hides nothing the staged
    /// crate could have bound to. A gap inside the closure is a different
    /// matter and must still be reported, because what it hides could have
    /// been the answer.
    ///
    /// The same unexpanded `include!` states both halves. In the staged crate
    /// it must leave the projection incomplete; in a dependent of the staged
    /// crate it must not. The half this pin guards is the first: a scope that
    /// dropped the staged crate's own mount, or a narrowing that ran wider
    /// than the request, would silently answer `Complete` here. The second half
    /// already held for this gap before the scope existed, measured by running
    /// the same test with the narrowing disabled -- a fragment-blocking gap in
    /// a blob the request never names does not reach it -- so treat that column
    /// as a statement of the rule rather than as its proof.
    #[test]
    fn a_gap_qualifies_the_staged_crate_and_a_dependent_of_it_does_not() {
        let outcomes = [false, true].map(|gap_in_provider| {
            let unexpanded = "include!(\"generated.rs\");\n";
            let fixture = InlineTestProject::with_language(Language::Rust)
                .file(
                    "Cargo.toml",
                    "[workspace]\nmembers=['provider','consumer']\nresolver='2'\n",
                )
                .file(
                    "provider/Cargo.toml",
                    "[package]\nname='provider'\nversion='0.1.0'\nedition='2021'\n",
                )
                .file(
                    "provider/src/lib.rs",
                    format!(
                        "pub fn target() {{}}\npub fn provider_caller() {{ target(); }}\n{}",
                        if gap_in_provider { unexpanded } else { "" }
                    ),
                )
                .file(
                    "consumer/Cargo.toml",
                    "[package]\nname='consumer'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nprovider={path='../provider'}\n",
                )
                .file(
                    "consumer/src/lib.rs",
                    format!(
                        "use provider::target;\npub fn caller() {{ target(); }}\n{}",
                        if gap_in_provider { "" } else { unexpanded }
                    ),
                )
                .build();
            let rust = RustAnalyzer::new(fixture.project_dyn());
            let (complete, _) = graph(
                build_rust_native_workspace_graph_for_files(
                    &rust,
                    &[fixture.file("provider/src/lib.rs")],
                    8,
                    &CancellationToken::new(),
                )
                .unwrap(),
            );
            (gap_in_provider, complete)
        });
        eprintln!("gap placement (gap in the staged crate, complete): {outcomes:?}");
        assert_eq!(
            outcomes,
            [(false, true), (true, false)],
            "the staged crate's own gap must qualify its answer and a dependent's must not: \
             {outcomes:?}"
        );
    }

    /// A mixed-language workspace must project the same complete Rust graph
    /// whether or not the request names paths.
    ///
    /// The Rust provider's input is the Rust-analyzable files of the request,
    /// or of the workspace when the request names none. A C++ header or a
    /// Python module sitting beside the crate is not an input the Rust pass
    /// owes an answer for, so neither request shape may report an
    /// incompleteness or a store failure because one is present. The rooted
    /// half of this is `scan_usages`'s
    /// `rooted_rust_usage_graph_ignores_other_languages_in_a_mixed_workspace`;
    /// the unrooted half was never covered, and it is the shape the
    /// whole-workspace corpus request uses.
    #[test]
    fn mixed_language_workspace_graph_is_complete_with_and_without_paths() {
        use crate::analyzer::{AnalyzerConfig, AnalyzerQueryScope, WorkspaceAnalyzer};
        use crate::searchtools::{UsageGraphParams, usage_graph};
        use std::sync::Arc;

        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        for (relative_path, source) in [
            (
                "Cargo.toml",
                "[package]\nname = \"mixed\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            (
                "src/lib.rs",
                "pub fn target() -> usize { 1 }\npub fn caller() -> usize { target() }\n",
            ),
            ("include/widget.h", "struct Widget { int value; };\n"),
            ("scripts/build.py", "def helper():\n    return 1\n"),
        ] {
            ProjectFile::new(root.clone(), relative_path)
                .write(source)
                .expect("write mixed-language fixture");
        }
        let project = crate::analyzer::TestProject::from_root_with_inferred_languages(&root)
            .expect("infer fixture languages");
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(project),
            AnalyzerConfig::default(),
        )
        .expect("mixed-language workspace");
        let analyzer = workspace.analyzer();

        for paths in [None, Some(vec!["src/lib.rs".to_string()])] {
            // The request boundary presents a recorded store failure instead
            // of the graph, so a graph that reports itself complete is only
            // half the answer: the outer scope is what the MCP service reads.
            let scope = AnalyzerQueryScope::new(analyzer);
            let graph = usage_graph(
                analyzer,
                UsageGraphParams {
                    include_tests: true,
                    paths: paths.clone(),
                    depth: 1,
                },
            );
            assert!(
                scope.store_error().is_none(),
                "paths={paths:?}: {:?}",
                scope.store_error()
            );
            assert!(graph.complete, "paths={paths:?}: {graph:#?}");
            assert!(
                graph
                    .edges
                    .iter()
                    .any(|edge| edge.from.ends_with("caller") && edge.to.ends_with("target")),
                "paths={paths:?}: {graph:#?}"
            );
        }
    }
}
