//! Typed completion of a usage-walk fill under its exact live reader.
use std::mem::size_of;
use std::sync::Arc;

#[cfg(test)]
use brokk_bifrost_analysis::analyzer::QueryReadIncomplete;
use brokk_bifrost_analysis::analyzer::derivation_host::{read_frame, rust_route_question_identity};
use brokk_bifrost_analysis::analyzer::i_analyzer::{AnalyzerQueryScope, CapturedCause};
use brokk_bifrost_analysis::analyzer::store::reader_binding::ReaderBinding;
use brokk_bifrost_core::allocation_size::allocation_size;
#[cfg(test)]
use brokk_bifrost_rust::usage_walks::walk_completion_digest;
use brokk_bifrost_rust::usage_walks::{
    LeafCompletion, WalkCauseKey, WalkCompletion, WalkCompletionReceipt,
    sorted_walk_completion_digest,
};
use brokk_bifrost_semantic::analyzer::semantic::derivation::UnavailableCause;

use super::RustAnalyzer;

/// Immutable evidence only: no analyzer, callback, token or reader connection.
/// A live inventory, rather than retaining this binding, proves its currency.
struct CompletionReceipt {
    binding: Option<ReaderBinding>,
    /// Interned causes in canonical presentation order, shared with every
    /// scope that recorded them. Their keys are computed once, here or earlier.
    reasons: Vec<Arc<CapturedCause>>,
    /// The sorted, deduplicated canonical keys of `reasons`, owned once.
    causes: Vec<WalkCauseKey>,
    digest: [u8; 32],
}

impl WalkCompletionReceipt for CompletionReceipt {
    fn matches_binding(&self, binding: &dyn std::any::Any) -> bool {
        binding
            .downcast_ref::<ReaderBinding>()
            .is_some_and(|binding| self.binding.as_ref() == Some(binding))
    }
    fn collect_causes(&self, into: &mut Vec<WalkCauseKey>) {
        into.extend_from_slice(&self.causes);
    }
    fn witness(&self) -> Option<&WalkCauseKey> {
        self.causes.first()
    }
    fn digest(&self) -> [u8; 32] {
        self.digest
    }
    fn allocated_bytes(&self) -> usize {
        allocation_size(size_of::<Self>() + 2 * size_of::<usize>())
            + allocation_size(self.reasons.capacity() * size_of::<Arc<CapturedCause>>())
            + allocation_size(self.causes.capacity() * size_of::<WalkCauseKey>())
            // Each cause key shares its CapturedCause's replay-key allocation,
            // which `retained_key_bytes` below charges once.
            + self
                .reasons
                .iter()
                .map(|cause| cause.reason().allocated_payload_bytes() + cause.retained_key_bytes())
                .sum::<usize>()
    }
    fn replay(&self) {
        // The containing memo restores captured read channels separately.
        brokk_bifrost_analysis::analyzer::common::replay_captured_causes(&self.reasons);
    }
}

/// Inspect an existing matching frame. Opening a new reader cannot authorize
/// an old receipt, even when the selected source snapshot happens to match.
fn with_live_binding<T>(
    analyzer: &RustAnalyzer,
    read: impl FnOnce(&ReaderBinding) -> Option<T>,
) -> Option<T> {
    if !read_frame::active() {
        return None;
    }
    let snapshot = analyzer
        .inner
        .selected_workspace_snapshots()
        .get("rust")?
        .clone();
    let identity = rust_route_question_identity(analyzer, analyzer.analyzer_store(), snapshot);
    read_frame::with_read_frame(
        &identity,
        || Err(UnavailableCause::MissingOperationReadFrame),
        |inventory| {
            let binding = inventory.derivation_reader_binding().ok()?;
            if !inventory.derivation_read_still_bound(&binding) {
                return None;
            }
            read(&binding)
        },
    )
    .ok()
    .flatten()
}

/// Encode every field of the returned typed cause and lookup attribution.
/// Hidden SQL tuples are not another read surface. Unsupported or operational
/// causes abort capture rather than manufacturing a settled-open answer.
#[cfg(test)]
fn cause_key(reason: &QueryReadIncomplete) -> Option<WalkCauseKey> {
    reason
        .canonical_replay_key()
        .map(WalkCauseKey::from_canonical_bytes)
}

pub(super) fn capture(analyzer: &RustAnalyzer, build: &mut dyn FnMut()) -> Option<WalkCompletion> {
    let before = with_live_binding(analyzer, |binding| Some(binding.clone()));
    let scope = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
    build();
    seal(analyzer, before, scope.captured_causes()).ok()
}

/// One leaf route read. A Closed read is never observed, so it builds no
/// receipt, binding re-check, cause set or digest.
pub(super) fn capture_leaf(analyzer: &RustAnalyzer, build: &mut dyn FnMut()) -> LeafCompletion {
    let before = with_live_binding(analyzer, |binding| Some(binding.clone()));
    let scope = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
    build();
    let reasons = scope.captured_causes();
    if reasons.is_empty() {
        return LeafCompletion::Closed;
    }
    match seal(analyzer, before, reasons) {
        Ok(completion) => LeafCompletion::Open(completion),
        Err(reasons) => LeafCompletion::Aborted(
            reasons
                .into_iter()
                .map(|cause| cause.reason().clone())
                .collect(),
        ),
    }
}

/// Build the receipt once from interned causes. Each cause key was computed
/// once, when its cause was first created; this only sorts and hashes them.
fn seal(
    analyzer: &RustAnalyzer,
    before: Option<ReaderBinding>,
    reasons: Vec<Arc<CapturedCause>>,
) -> Result<WalkCompletion, Vec<Arc<CapturedCause>>> {
    let Some(mut causes) = reasons
        .iter()
        .map(|cause| cause.replay_key().cloned().map(WalkCauseKey::from_shared))
        .collect::<Option<Vec<_>>>()
    else {
        return Err(reasons);
    };
    causes.sort_unstable();
    causes.dedup();
    let digest = sorted_walk_completion_digest(&causes);
    let binding = before
        .filter(|before| with_live_binding(analyzer, |after| Some(after == before)) == Some(true));
    Ok(WalkCompletion::captured(CompletionReceipt {
        binding,
        reasons,
        causes,
        digest,
    }))
}

pub(super) fn is_current(analyzer: &RustAnalyzer, completion: &WalkCompletion) -> bool {
    with_live_binding(analyzer, |current| {
        Some(completion.receipt().matches_binding(current))
    }) == Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::capture_query_reads;
    use brokk_bifrost_analysis::analyzer::i_analyzer::{QueryLookupProvenance, QueryReadReceipt};
    use brokk_bifrost_core::analyzer::model::{Language, ProjectFile};
    use brokk_bifrost_core::analyzer::query_token::QueryScope;
    use brokk_bifrost_rust::graph_support::with_usage_read_frame;
    use brokk_bifrost_rust::usage_walks::{RustUsageWalks, Walked};

    fn normalized(
        answer: &brokk_bifrost_core::hash::HashMap<
            String,
            Vec<brokk_bifrost_rust::usage::RustOriginRoute>,
        >,
    ) -> Vec<(String, Vec<String>)> {
        let mut rows = answer
            .iter()
            .map(|(name, routes)| {
                // Derived Debug covers every route field; normalize container order only.
                let mut routes: Vec<_> = routes.iter().map(|route| format!("{route:?}")).collect();
                routes.sort();
                (name.clone(), routes)
            })
            .collect::<Vec<_>>();
        rows.sort();
        rows
    }

    fn cause_set(reasons: &[QueryReadIncomplete]) -> Vec<WalkCauseKey> {
        let mut causes = reasons
            .iter()
            .map(|reason| cause_key(reason).expect("stable returned cause"))
            .collect::<Vec<_>>();
        causes.sort();
        causes.dedup();
        causes
    }

    /// Whether a returned cause names `file`. A gap payload embeds the `Debug`
    /// of the host-normalized relative path, so the needle must use the same
    /// rendering: a literal `src/a.rs` only matches where `/` is the separator.
    fn cause_names_file(reasons: &[QueryReadIncomplete], file: &ProjectFile) -> bool {
        let needle = format!("{:?}", file.rel_path());
        reasons.iter().any(|cause| {
            matches!(
                cause.base_cause(),
                QueryReadIncomplete::SemanticEvidenceGap(text) if text.contains(needle.as_str())
            )
        })
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13024: alias and cold workqueue ordering leaked into diagnostic bytes and first cause"
    )]
    fn branch_and_late_edge_diagnostics_have_canonical_bytes() {
        use super::super::route_kinds::{render_route_evidence_gaps, route_evidence_gaps};
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("src/a.rs", "pub struct A;")
            .build();
        let workspace = project.workspace_analyzer(Default::default());
        let analyzer = workspace.analyzer();
        let reason = |name: &str| {
            QueryReadIncomplete::SemanticEvidenceGap(
                format!("Rust route evidence is incomplete for units {name}").into(),
            )
        };
        for (warm, cold) in [
            (vec!["B", "C"], vec!["C", "B"]),
            (vec!["B", "C", "D"], vec!["C", "B", "D"]),
        ] {
            let run = |order: Vec<&str>| {
                let scope = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
                let (_, receipt) = QueryReadReceipt::capture(analyzer, || {
                    for name in order {
                        analyzer.record_query_incomplete(reason(name));
                    }
                });
                (
                    scope.read_completion(),
                    scope.captured_read_incompleteness(),
                    format!("{receipt:?}"),
                )
            };
            let warm = run(warm);
            let cold = run(cold);
            assert_eq!(warm, cold);
            assert_eq!(warm.0, Err(reason("B")));
            let component = |name| {
                QueryReadReceipt::capture_deferred(analyzer, || {
                    analyzer.record_query_incomplete(reason(name));
                })
                .1
            };
            let mut bc = component("B");
            bc.extend(&component("C"));
            let mut cb = component("C");
            cb.extend(&component("B"));
            assert_eq!(format!("{bc:?}"), format!("{cb:?}"));

            assert_eq!(
                render_route_evidence_gaps(&warm.1),
                render_route_evidence_gaps(&cold.1)
            );
            let duplicate = vec![reason("C"), reason("B"), reason("C")];
            let sorted = vec![reason("B"), reason("C"), reason("C")];
            assert_eq!(route_evidence_gaps(&duplicate).len(), 3);
            assert_eq!(
                render_route_evidence_gaps(&duplicate),
                render_route_evidence_gaps(&sorted)
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13024: canonical first cause must keep concrete unit evidence ahead of a real empty-unit gap"
    )]
    fn canonical_cause_prefers_unit_evidence_without_losing_the_empty_gap() {
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", "pub struct A;")
            .build();
        let workspace = project.workspace_analyzer(Default::default());
        let analyzer = workspace.analyzer();
        let specific = QueryReadIncomplete::SemanticEvidenceGap(
            format!(
                "selected Rust crate membership is incomplete: {:02x?}",
                [[1u8; 32]]
            )
            .into(),
        );
        let empty = QueryReadIncomplete::SemanticEvidenceGap(
            "Rust route evidence is incomplete for units []".into(),
        );
        assert!(specific.answer_order_key() < empty.answer_order_key());
        for empty_first in [false, true] {
            let scope = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
            if empty_first {
                super::super::route_kinds::record_route_evidence_gap(analyzer, &[]);
            }
            analyzer.record_query_incomplete(specific.clone());
            if !empty_first {
                super::super::route_kinds::record_route_evidence_gap(analyzer, &[]);
            }
            assert_eq!(scope.read_completion(), Err(specific.clone()));
            assert_eq!(
                scope.captured_read_incompleteness(),
                vec![specific.clone(), empty.clone()]
            );
            assert_eq!(
                super::super::route_kinds::route_evidence_gaps(
                    &scope.captured_read_incompleteness()
                ),
                vec!["Rust route evidence is incomplete for units []"],
            );
        }
    }

    #[cfg(unix)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13024: lossy path encoding merged distinct attributed incomplete-read causes"
    )]
    fn canonical_cause_identity_preserves_non_utf8_paths() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("src/a.rs", "pub struct A;")
            .build();
        let make = |byte| {
            let path = OsString::from_vec(vec![b's', b'r', b'c', b'/', byte, b'.', b'r', b's']);
            QueryReadIncomplete::SemanticEvidenceGap("same gap".into()).attributed(
                QueryLookupProvenance {
                    file: project.file("src/a.rs").with_rel_path(path),
                    byte_span: 0..4,
                    name: "A".into(),
                    tier: "binding",
                },
            )
        };
        let a = make(0xfe);
        let b = make(0xff);
        assert_ne!(a, b);
        assert_eq!(
            a.lookup_provenance()
                .unwrap()
                .file
                .rel_path()
                .to_string_lossy(),
            b.lookup_provenance()
                .unwrap()
                .file
                .rel_path()
                .to_string_lossy(),
            "pin the lossy-path collision",
        );
        assert_ne!(a.canonical_replay_key(), b.canonical_replay_key());
        let a = cause_key(&a).unwrap();
        let b = cause_key(&b).unwrap();
        assert_ne!(
            walk_completion_digest(vec![a.clone()]),
            walk_completion_digest(vec![b.clone()])
        );
        let both = walk_completion_digest(vec![a.clone(), b.clone()]);
        assert_ne!(both, walk_completion_digest(vec![a.clone()]));
        assert_eq!(both, walk_completion_digest(vec![b, a]));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13024: attributed cause keys merged equal relative paths from distinct roots"
    )]
    fn canonical_cause_identity_covers_kind_body_and_every_lookup_field() {
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("src/a.rs", "pub struct A;")
            .file("src/b.rs", "pub struct B;")
            .build();
        let key = |file, byte_span, name: &str, tier| {
            QueryReadIncomplete::SemanticEvidenceGap("gap".into())
                .attributed(QueryLookupProvenance {
                    file,
                    byte_span,
                    name: name.into(),
                    tier,
                })
                .canonical_replay_key()
                .unwrap()
        };
        // Both replay identity and presentation preserve the complete file
        // identity, including roots of other projects named by a typed gap.
        let other = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("src/a.rs", "pub struct A;")
            .build();
        let attributed = |file| {
            QueryReadIncomplete::SemanticEvidenceGap("gap".into()).attributed(
                QueryLookupProvenance {
                    file,
                    byte_span: 0..4,
                    name: "A".into(),
                    tier: "binding",
                },
            )
        };
        assert_ne!(
            attributed(project.file("src/a.rs")).answer_order_key(),
            attributed(other.file("src/a.rs")).answer_order_key(),
        );
        assert_ne!(
            QueryReadIncomplete::StructureUnavailable(project.file("src/a.rs")).answer_order_key(),
            QueryReadIncomplete::StructureUnavailable(other.file("src/a.rs")).answer_order_key(),
        );
        let baseline = key(project.file("src/a.rs"), 0..4, "A", "binding");
        assert_eq!(
            baseline,
            key(project.file("src/a.rs"), 0..4, "A", "binding")
        );
        for changed in [
            key(other.file("src/a.rs"), 0..4, "A", "binding"),
            key(project.file("src/b.rs"), 0..4, "A", "binding"),
            key(project.file("src/a.rs"), 1..4, "A", "binding"),
            key(project.file("src/a.rs"), 0..5, "A", "binding"),
            key(project.file("src/a.rs"), 0..4, "B", "binding"),
            key(project.file("src/a.rs"), 0..4, "A", "route"),
        ] {
            assert_ne!(baseline, changed);
        }
        assert_ne!(
            QueryReadIncomplete::SemanticEvidenceGap("a".into()).canonical_replay_key(),
            QueryReadIncomplete::SemanticEvidenceGap("b".into()).canonical_replay_key()
        );
        assert_ne!(
            QueryReadIncomplete::SemanticEvidenceGap("a".into()).canonical_replay_key(),
            QueryReadIncomplete::ArtifactUnavailable("a".into()).canonical_replay_key()
        );
        assert!(
            QueryReadIncomplete::Cancelled
                .canonical_replay_key()
                .is_none()
        );
        assert!(
            QueryReadIncomplete::ProofStopped {
                reason: "unknown_test_stop",
                cause: None
            }
            .canonical_replay_key()
            .is_none()
        );
    }

    #[test]
    fn open_branch_alias_replays_cold_diagnostic_cause_order() {
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"branches\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "src/lib.rs",
                "pub mod a; pub mod b; pub mod c; pub mod leaf_b; pub mod leaf_c; pub use a::*;\n",
            )
            .file("src/a.rs", "pub use crate::b::*; pub use crate::c::*;\n")
            .file("src/b.rs", "pub use crate::leaf_b::B;\n")
            .file("src/c.rs", "pub use crate::leaf_c::C;\n")
            .file("src/leaf_b.rs", "pub struct B;\n")
            .file("src/leaf_c.rs", "pub struct C;\n")
            .build();
        let workspace = project.certified_workspace_analyzer(Default::default());
        let analyzer = brokk_bifrost_analysis::analyzer::resolve_analyzer::<RustAnalyzer>(
            workspace.analyzer(),
        )
        .unwrap();
        workspace.store().unwrap().execute_selection_publication(|conn| {
            let _fixture = brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(conn);
            for (subject, path) in [("crate::b", "src/b.rs"), ("crate::c", "src/c.rs")] {
                conn.execute(
                    "INSERT INTO rust_resolution_unit_summary_gaps(summary_id,gap_kind,subject,detail) SELECT summary_id,'unknown_activation',?1,jsonb(?2) FROM rust_resolution_unit_summary_contexts",
                    rusqlite::params![subject, serde_json::json!({"path": path}).to_string()],
                ).unwrap();
            }
        });
        let root = project.file("src/lib.rs");
        let alias = project.file("src/a.rs");
        let warm = {
            let scope = AnalyzerQueryScope::new(analyzer);
            with_usage_read_frame(analyzer, || {
                capture(analyzer, &mut || {}).unwrap();
                let walks = RustUsageWalks::new(analyzer, scope.token()).unwrap();
                let root_module = walks.physical_root_of(&root).unwrap();
                walks.bindings_at(&root, &root_module).unwrap();
                let module = walks.physical_root_of(&alias).unwrap();
                let hits = || {
                    analyzer
                        .walk_caches
                        .hit_counts()
                        .into_iter()
                        .find(|(name, _)| *name == "rust.walk.module_bindings")
                        .unwrap()
                        .1
                };
                let before = hits();
                let (value, receipt) = QueryReadReceipt::capture(analyzer, || {
                    walks.bindings_at(&alias, &module).unwrap()
                });
                assert!(hits() > before, "exercise the settled branch alias");
                assert!(!value.is_closed());
                receipt
            })
        };
        let scratch = RustAnalyzer::from_inner(analyzer.inner.clone());
        let scope = AnalyzerQueryScope::new(&scratch);
        let cold = with_usage_read_frame(&scratch, || {
            capture(&scratch, &mut || {}).unwrap();
            let walks = RustUsageWalks::new(&scratch, scope.token()).unwrap();
            let module = walks.physical_root_of(&alias).unwrap();
            let (value, receipt) =
                QueryReadReceipt::capture(&scratch, || walks.bindings_at(&alias, &module).unwrap());
            assert!(!value.is_closed());
            receipt
        });
        assert_eq!(
            cause_set(warm.incomplete_reasons()),
            cause_set(cold.incomplete_reasons())
        );
        let gaps = super::super::route_kinds::route_evidence_gaps;
        let warm_gaps = gaps(warm.incomplete_reasons());
        let cold_gaps = gaps(cold.incomplete_reasons());
        assert!(
            cold_gaps.len() >= 2,
            "exercise independent Open branches: {cold_gaps:?}"
        );
        assert_eq!(
            warm_gaps, cold_gaps,
            "the actual diagnostic payload must preserve cold order"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13024: a Closed alias inherited an independent Open sibling's read channels"
    )]
    fn closed_alias_of_an_open_group_preserves_cold_read_eligibility() {
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"mixed\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "src/lib.rs",
                "pub mod open; pub mod closed; pub use open::*; pub use closed::*;\n",
            )
            .file("src/open.rs", "pub struct Open;\n")
            .file("src/closed.rs", "pub struct Closed;\n")
            .build();
        let workspace = project.certified_workspace_analyzer(Default::default());
        let analyzer = brokk_bifrost_analysis::analyzer::resolve_analyzer::<RustAnalyzer>(
            workspace.analyzer(),
        )
        .unwrap();
        workspace.store().unwrap().execute_selection_publication(|conn| {
            let _fixture = brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(conn);
            conn.execute(
                "INSERT INTO rust_resolution_unit_summary_gaps(summary_id,gap_kind,subject,detail) SELECT summary_id,'unknown_activation','crate::open',jsonb(?1) FROM rust_resolution_unit_summary_contexts",
                [r#"{"path":"src/open.rs"}"#],
            ).unwrap();
        });
        let root = project.file("src/lib.rs");
        let closed = project.file("src/closed.rs");
        let open = project.file("src/open.rs");
        let (warm_value, warm_receipt, warm_reads, warm_open_receipt, warm_open_reads) = {
            let scope = AnalyzerQueryScope::new(analyzer);
            with_usage_read_frame(analyzer, || {
                capture(analyzer, &mut || {}).unwrap();
                let walks = RustUsageWalks::new(analyzer, scope.token()).unwrap();
                let root_module = walks.physical_root_of(&root).unwrap();
                let group = walks.bindings_at(&root, &root_module).unwrap();
                assert!(!group.is_closed(), "the root consumes the Open sibling");
                let module = walks.physical_root_of(&closed).unwrap();
                let hits = || {
                    analyzer
                        .walk_caches
                        .hit_counts()
                        .into_iter()
                        .find(|(name, _)| *name == "rust.walk.module_bindings")
                        .unwrap()
                        .1
                };
                let before = hits();
                let ((value, receipt), reads) = capture_query_reads(analyzer, || {
                    QueryReadReceipt::capture(analyzer, || {
                        walks.bindings_at(&closed, &module).unwrap()
                    })
                });
                assert!(hits() > before, "exercise the settled alias hit");
                assert!(
                    value.is_closed(),
                    "this alias does not depend on its sibling"
                );
                let module = walks.physical_root_of(&open).unwrap();
                let ((open_value, open_receipt), open_reads) =
                    capture_query_reads(analyzer, || {
                        QueryReadReceipt::capture(analyzer, || {
                            walks.bindings_at(&open, &module).unwrap()
                        })
                    });
                assert!(!open_value.is_closed());
                (value, receipt, reads, open_receipt, open_reads)
            })
        };
        let scratch = RustAnalyzer::from_inner(analyzer.inner.clone());
        let scope = AnalyzerQueryScope::new(&scratch);
        let ((cold_value, cold_receipt), cold_reads) = with_usage_read_frame(&scratch, || {
            capture(&scratch, &mut || {}).unwrap();
            let walks = RustUsageWalks::new(&scratch, scope.token()).unwrap();
            let module = walks.physical_root_of(&closed).unwrap();
            capture_query_reads(&scratch, || {
                QueryReadReceipt::capture(&scratch, || walks.bindings_at(&closed, &module).unwrap())
            })
        });
        assert!(cold_value.is_closed());
        assert_eq!(*warm_value, *cold_value);
        assert_eq!(
            cause_set(warm_receipt.incomplete_reasons()),
            cause_set(cold_receipt.incomplete_reasons())
        );
        assert!(cold_reads.is_bounded());
        assert_eq!(warm_reads.channels().unattributed_reads, 0);
        assert_eq!(
            warm_reads.channels(),
            cold_reads.channels(),
            "a Closed alias cannot inherit its Open sibling's refusal channels"
        );
        assert_eq!(
            warm_reads.digest(),
            cold_reads.digest(),
            "the alias replays only its own reachable named reads"
        );
        let scratch_open = RustAnalyzer::from_inner(analyzer.inner.clone());
        let scope = AnalyzerQueryScope::new(&scratch_open);
        let ((open_value, open_receipt), open_reads) = with_usage_read_frame(&scratch_open, || {
            capture(&scratch_open, &mut || {}).unwrap();
            let walks = RustUsageWalks::new(&scratch_open, scope.token()).unwrap();
            let module = walks.physical_root_of(&open).unwrap();
            capture_query_reads(&scratch_open, || {
                QueryReadReceipt::capture(&scratch_open, || {
                    walks.bindings_at(&open, &module).unwrap()
                })
            })
        });
        assert!(!open_value.is_closed());
        assert_eq!(
            warm_open_reads.channels().unattributed_reads,
            16,
            "the Open sibling keeps its own refusal channels"
        );
        assert_eq!(warm_open_reads.channels(), open_reads.channels());
        assert_eq!(warm_open_reads.digest(), open_reads.digest());
        assert_eq!(
            cause_set(warm_open_receipt.incomplete_reasons()),
            cause_set(open_receipt.incomplete_reasons())
        );
    }

    #[test]
    fn settled_open_hits_replay_returned_causes_and_refuse_another_reader() {
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"shared\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[lib]\npath = \"src/shared.rs\"\n[[bin]]\nname = \"shared-bin\"\npath = \"src/shared.rs\"\n")
            .file("src/shared.rs", "pub mod a; pub mod b; pub use a::*; pub use b::*;\n")
            .file("src/a.rs", "pub use crate::b::*; pub struct A;\n")
            .file("src/b.rs", "pub use crate::a::*; pub struct B;\n")
            .build();
        let workspace = project.certified_workspace_analyzer(Default::default());
        let analyzer = brokk_bifrost_analysis::analyzer::resolve_analyzer::<RustAnalyzer>(
            workspace.analyzer(),
        )
        .unwrap();
        let store = workspace.store().unwrap();
        let summary_count = store.execute_selection_publication(|conn| {
            let _fixture =
                brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(conn);
            let summary_count = conn.execute(
                "UPDATE rust_resolution_unit_summary_contexts SET broad_complete=0",
                [],
            ).unwrap();
            for (subject, path) in [("crate::a", "src/a.rs"), ("crate::b", "src/b.rs")] {
                conn.execute(
                    "INSERT INTO rust_resolution_unit_summary_gaps(summary_id,gap_kind,subject,detail) SELECT summary_id,'unknown_activation',?1,jsonb(?2) FROM rust_resolution_unit_summary_contexts",
                    rusqlite::params![subject, serde_json::json!({"path": path}).to_string()],
                ).unwrap();
            }
            summary_count
        });
        assert_eq!(
            summary_count, 2,
            "the same source has two independently incomplete unit inputs"
        );
        let source = project.file("src/shared.rs");
        let scope = AnalyzerQueryScope::new(analyzer);
        let (first, reasons, first_digest, alias_value, alias_reasons) =
            with_usage_read_frame(analyzer, || {
                capture(analyzer, &mut || {}).expect("pin reader before cache capture");
                let lookup = || {
                    let walks = RustUsageWalks::new(analyzer, scope.token()).unwrap();
                    let value = walks.origin_routes_of(&source).unwrap();
                    assert!(!value.is_closed());
                    assert!(!walks.routes_are_complete());
                    let empty = walks.files_in_module_package("absent_13024");
                    assert!(empty.is_empty());
                    assert!(!empty.is_closed(), "Open empty never proves absence");
                    value
                };
                let ((first, cold), cold_reads) =
                    capture_query_reads(analyzer, || QueryReadReceipt::capture(analyzer, lookup));
                let ((second, hit), hit_reads) =
                    capture_query_reads(analyzer, || QueryReadReceipt::capture(analyzer, lookup));
                assert!(
                    cold_reads.channels().unattributed_reads > 0,
                    "stable Open content still refuses policy-unit reuse"
                );
                assert_eq!(
                    cold_reads.channels(),
                    hit_reads.channels(),
                    "replay preserves refusal counts without re-marking typed causes"
                );
                assert_eq!(hit_reads.channels().execution_dependences, 0);
                assert!(
                    Walked::ptr_eq(&first, &second),
                    "same reader reuses the real Open fill: causes={:?}; hits={:?}",
                    cold.incomplete_reasons(),
                    analyzer.walk_caches.hit_counts()
                );
                assert_eq!(cold.incomplete_reasons(), hit.incomplete_reasons());
                assert_eq!(
                    cold.digest(),
                    hit.digest(),
                    "the hit preserves named input reads"
                );
                assert!(!cold.incomplete_reasons().is_empty());
                let walks = RustUsageWalks::new(analyzer, scope.token()).unwrap();
                let alias_file = project.file("src/b.rs");
                let module = walks.physical_root_of(&alias_file).unwrap();
                let hits = || {
                    analyzer
                        .walk_caches
                        .hit_counts()
                        .into_iter()
                        .find(|(name, _)| *name == "rust.walk.module_bindings")
                        .unwrap()
                        .1
                };
                let before = hits();
                let (alias, alias_receipt) = QueryReadReceipt::capture(analyzer, || {
                    walks.bindings_at(&alias_file, &module).unwrap()
                });
                assert!(hits() > before, "the settled cycle publishes the other key");
                assert!(!alias.is_closed());
                let mut build = || drop(lookup());
                let completion = capture(analyzer, &mut build).unwrap();
                assert!(is_current(analyzer, &completion));
                (
                    first,
                    cold.incomplete_reasons().to_vec(),
                    completion.digest(),
                    alias,
                    alias_receipt.incomplete_reasons().to_vec(),
                )
            });
        let next = with_usage_read_frame(analyzer, || {
            let walks = RustUsageWalks::new(analyzer, scope.token()).unwrap();
            walks.origin_routes_of(&source).unwrap()
        });
        assert!(
            !Walked::ptr_eq(&first, &next),
            "different reader binding refuses reuse"
        );
        assert_eq!(normalized(&first), normalized(&next));
        drop(scope);
        {
            let scratch = RustAnalyzer::from_inner(analyzer.inner.clone());
            let scratch_scope = AnalyzerQueryScope::new(&scratch);
            with_usage_read_frame(&scratch, || {
                let walks = RustUsageWalks::new(&scratch, scratch_scope.token()).unwrap();
                let alias_file = project.file("src/b.rs");
                let module = walks.physical_root_of(&alias_file).unwrap();
                let (cold, receipt) = QueryReadReceipt::capture(&scratch, || {
                    walks.bindings_at(&alias_file, &module).unwrap()
                });
                let normalize =
                    |bindings: &[brokk_bifrost_rust::usage_walks::RustModuleBinding]| {
                        let mut rows = bindings
                            .iter()
                            .map(|binding| format!("{binding:?}"))
                            .collect::<Vec<_>>();
                        rows.sort();
                        rows
                    };
                assert_eq!(normalize(&cold), normalize(&alias_value));
                assert_eq!(
                    cause_set(receipt.incomplete_reasons()),
                    cause_set(&alias_reasons),
                    "alias hit completion equals its independent cold SCC"
                );
            });
        }
        // Remove an actually returned placement cause. Both broad bits and
        // every source byte remain unchanged; the B placement stays undecided.
        assert!(
            cause_names_file(&reasons, &project.file("src/a.rs")),
            "the returned causes must name the A placement: {reasons:#?}"
        );
        let open_units: usize = store.execute_selection_publication(|conn| {
            let _fixture = brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(conn);
            conn.execute("DELETE FROM rust_resolution_unit_summary_gaps WHERE gap_kind='unknown_activation' AND subject='crate::a'", []).unwrap();
            conn.query_row(
                "SELECT count(*) FROM rust_resolution_unit_summary_contexts WHERE broad_complete=0",
                [], |row| row.get(0),
            ).unwrap()
        });
        assert_eq!(open_units, summary_count, "all broad bits remain false");
        let scope = AnalyzerQueryScope::new(analyzer);
        let changed = with_usage_read_frame(analyzer, || {
            let mut answer = None;
            let mut build = || {
                let walks = RustUsageWalks::new(analyzer, scope.token()).unwrap();
                let (value, receipt) = QueryReadReceipt::capture(analyzer, || {
                    walks.origin_routes_of(&source).unwrap()
                });
                assert!(!value.is_closed());
                assert!(!walks.routes_are_complete());
                answer = Some((value, receipt.incomplete_reasons().to_vec()));
            };
            let completion = capture(analyzer, &mut build).unwrap();
            assert_ne!(
                completion.digest(),
                first_digest,
                "Open(A,B) differs from Open(B) despite remaining Open"
            );
            answer.unwrap()
        });
        assert_ne!(changed.1, reasons, "an actual returned cause changed");
        assert!(
            !cause_names_file(&changed.1, &project.file("src/a.rs")),
            "the removed A placement cause must be absent: {:#?}",
            changed.1
        );
        assert!(
            cause_names_file(&changed.1, &project.file("src/b.rs")),
            "the B placement cause must remain: {:#?}",
            changed.1
        );
        drop(scope); // End this operation before mutating its inventory again.
        let scratch = RustAnalyzer::from_inner(analyzer.inner.clone());
        let scope = AnalyzerQueryScope::new(&scratch);
        with_usage_read_frame(&scratch, || {
            let walks = RustUsageWalks::new(&scratch, scope.token()).unwrap();
            let (value, receipt) =
                QueryReadReceipt::capture(&scratch, || walks.origin_routes_of(&source).unwrap());
            assert_eq!(
                normalized(&value),
                normalized(&changed.0),
                "incremental and scratch values agree"
            );
            assert_eq!(receipt.incomplete_reasons(), changed.1);
        });
        drop(scope);
        // The reverse edit adds A back without closing B or changing a broad
        // bit. A newly allocated SQL gap row has the same returned typed cause.
        store.execute_selection_publication(|conn| {
            let _fixture = brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(conn);
            conn.execute(
                "INSERT INTO rust_resolution_unit_summary_gaps(summary_id,gap_kind,subject,detail) SELECT summary_id,'unknown_activation','crate::a',jsonb(?1) FROM rust_resolution_unit_summary_contexts",
                [r#"{"path":"src/a.rs"}"#],
            ).unwrap();
        });
        let read_restored = |reader: &RustAnalyzer| {
            let scope = AnalyzerQueryScope::new(reader);
            with_usage_read_frame(reader, || {
                capture(reader, &mut || {}).expect("pin operation reader");
                let walks = RustUsageWalks::new(reader, scope.token()).unwrap();
                let mut result = None;
                let mut build = || {
                    let value = walks.origin_routes_of(&source).unwrap();
                    assert!(!value.is_closed());
                    let empty = walks.files_in_module_package("absent_13024");
                    assert!(empty.is_empty() && !empty.is_closed());
                    result = Some(normalized(&value));
                };
                let completion = capture(reader, &mut build).unwrap();
                let mut causes = vec![];
                completion.receipt().collect_causes(&mut causes);
                causes.sort();
                causes.dedup();
                (result.unwrap(), causes, completion.digest())
            })
        };
        let restored = read_restored(analyzer);
        assert_eq!(
            restored.1,
            cause_set(&reasons),
            "adding A restores the full returned cause set"
        );
        assert_eq!(restored.2, first_digest);
        assert_eq!(restored.0, normalized(&first));
        let scratch = RustAnalyzer::from_inner(analyzer.inner.clone());
        assert_eq!(
            restored,
            read_restored(&scratch),
            "Open cause addition agrees with scratch"
        );
        for broad in [1, 0] {
            store.execute_selection_publication(move |conn| {
                let _fixture = brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(conn);
                conn.execute("DELETE FROM rust_resolution_unit_summary_gaps WHERE gap_kind='unknown_activation' AND subject IN ('crate::a','crate::b')", []).unwrap();
                conn.execute("UPDATE rust_resolution_unit_summary_contexts SET broad_complete=?1", [broad]).unwrap();
            });
            let scope = AnalyzerQueryScope::new(analyzer);
            let (warm, warm_reasons) = with_usage_read_frame(analyzer, || {
                let lookup = || {
                    let walks = RustUsageWalks::new(analyzer, scope.token()).unwrap();
                    let value = walks.origin_routes_of(&source).unwrap();
                    assert_eq!(value.is_closed(), broad == 1);
                    assert_eq!(walks.routes_are_complete(), broad == 1);
                    value
                };
                let (first, receipt) = QueryReadReceipt::capture(analyzer, lookup);
                let (second, hit) = QueryReadReceipt::capture(analyzer, lookup);
                assert!(Walked::ptr_eq(&first, &second));
                assert_eq!(
                    cause_set(receipt.incomplete_reasons()),
                    cause_set(hit.incomplete_reasons())
                );
                (first, receipt.incomplete_reasons().to_vec())
            });
            let scratch = RustAnalyzer::from_inner(analyzer.inner.clone());
            let scratch_scope = AnalyzerQueryScope::new(&scratch);
            with_usage_read_frame(&scratch, || {
                let walks = RustUsageWalks::new(&scratch, scratch_scope.token()).unwrap();
                let (value, receipt) = QueryReadReceipt::capture(&scratch, || {
                    walks.origin_routes_of(&source).unwrap()
                });
                assert_eq!(value.is_closed(), warm.is_closed());
                assert_eq!(normalized(&value), normalized(&warm));
                assert_eq!(
                    cause_set(receipt.incomplete_reasons()),
                    cause_set(&warm_reasons)
                );
            });
        }
    }

    #[test]
    fn leaf_capture_keeps_open_reasons_and_owns_no_closed_receipt() {
        use brokk_bifrost_analysis::IAnalyzer as _;
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("src/a.rs", "pub struct A;")
            .build();
        let workspace = project.workspace_analyzer(Default::default());
        let analyzer = brokk_bifrost_analysis::analyzer::resolve_analyzer::<RustAnalyzer>(
            workspace.analyzer(),
        )
        .unwrap();
        let gap = |text: &str| QueryReadIncomplete::SemanticEvidenceGap(text.into());
        // Closed leaf: no receipt, so nothing can be observed for it.
        assert!(matches!(
            capture_leaf(analyzer, &mut || {}),
            LeafCompletion::Closed
        ));
        // Open leaf: its typed cause survives with the v1 digest of that cause.
        let LeafCompletion::Open(open) = capture_leaf(analyzer, &mut || {
            analyzer.record_query_incomplete(gap("leaf open"))
        }) else {
            panic!("an Open leaf read must produce a receipt");
        };
        let mut causes = vec![];
        open.receipt().collect_causes(&mut causes);
        assert_eq!(causes, cause_set(&[gap("leaf open")]));
        assert_eq!(open.digest(), walk_completion_digest(causes));
        // Operational causes abort, never settle as Closed.
        assert!(matches!(
            capture_leaf(analyzer, &mut || analyzer
                .record_query_incomplete(QueryReadIncomplete::Cancelled)),
            LeafCompletion::Aborted(_)
        ));
        // A fill whose other leaf reads are Closed still carries the Open leaf's
        // cause: unknown never becomes empty.
        let fill = capture(analyzer, &mut || {
            assert!(matches!(
                capture_leaf(analyzer, &mut || {}),
                LeafCompletion::Closed
            ));
            assert!(matches!(
                capture_leaf(analyzer, &mut || analyzer
                    .record_query_incomplete(gap("inner open"))),
                LeafCompletion::Open(_)
            ));
            assert!(matches!(
                capture_leaf(analyzer, &mut || {}),
                LeafCompletion::Closed
            ));
        })
        .expect("deterministic causes settle");
        assert!(fill.is_open());
        let mut causes = vec![];
        fill.receipt().collect_causes(&mut causes);
        assert_eq!(causes, cause_set(&[gap("inner open")]));
    }

    #[test]
    fn sorted_digest_is_byte_identical_to_the_v1_digest() {
        let cause =
            |n: u32| WalkCauseKey::from_canonical_bytes(format!("cause-{n:05}").into_bytes());
        let mut seed = 0x9e3779b9u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        for _ in 0..200 {
            let len = (next() % 40) as usize;
            let raw: Vec<_> = (0..len).map(|_| cause(next() % 30)).collect();
            let mut sorted = raw.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(
                walk_completion_digest(raw.clone()),
                sorted_walk_completion_digest(&sorted),
            );
        }
        assert_eq!(
            walk_completion_digest(vec![]),
            sorted_walk_completion_digest(&[])
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13024: singleton completion presentation keys grew after fixed cache admission"
    )]
    fn singleton_completion_charge_is_stable_after_mixed_replay() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("src/a.rs", "pub struct A;")
            .build();
        let workspace = project.certified_workspace_analyzer(Default::default());
        let analyzer = brokk_bifrost_analysis::analyzer::resolve_analyzer::<RustAnalyzer>(
            workspace.analyzer(),
        )
        .unwrap();
        let completion = capture(analyzer, &mut || {
            analyzer.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
                "a single retained cause".into(),
            ));
        })
        .unwrap();
        let admitted = completion.receipt().allocated_bytes();
        let consumer = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
        analyzer.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
            "a different consumer cause".into(),
        ));
        completion.replay();
        assert_eq!(consumer.captured_causes().len(), 2);
        assert_eq!(
            completion.receipt().allocated_bytes(),
            admitted,
            "mixed replay must not grow an already charged completion"
        );
    }

    #[test]
    fn replay_attaches_interned_causes_without_recomputing_keys() {
        use brokk_bifrost_analysis::analyzer::common::replay_captured_causes;
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("src/a.rs", "pub struct A;")
            .build();
        let workspace = project.workspace_analyzer(Default::default());
        let analyzer = workspace.analyzer();
        let causes = (0..5)
            .map(|n| {
                CapturedCause::new(QueryReadIncomplete::SemanticEvidenceGap(
                    format!("replayed {n}").into(),
                ))
            })
            .collect::<Vec<_>>();
        let outer = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
        replay_captured_causes(&causes);
        // The first replay may compute each key once; no later replay may.
        let after_first = causes
            .iter()
            .map(|c| c.key_computations())
            .collect::<Vec<_>>();
        assert!(after_first.iter().all(|n| *n <= 2));
        for _ in 0..50 {
            let inner = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
            replay_captured_causes(&causes);
            assert_eq!(inner.captured_causes().len(), causes.len());
        }
        assert_eq!(
            after_first,
            causes
                .iter()
                .map(|c| c.key_computations())
                .collect::<Vec<_>>(),
            "replay must attach stored causes, not recompute their keys",
        );
        assert_eq!(outer.captured_causes().len(), causes.len());
    }

    /// Real Rust sources (this repository's own modules), every unit made
    /// incompletely activated: each file's cold fill and its memo hit must
    /// produce the same typed-cause set and the same v1 digest, and that
    /// digest must equal the reference recomputed from the full cause set.
    #[test]
    fn replayed_memo_equals_fresh_fill_on_real_sources() {
        const SOURCES: &[(&str, &str)] = &[
            (
                "cache",
                include_str!("../../../../bifrost-rust/src/cache.rs"),
            ),
            ("cfg", include_str!("../../../../bifrost-rust/src/cfg.rs")),
            (
                "cfg_if",
                include_str!("../../../../bifrost-rust/src/cfg_if.rs"),
            ),
            (
                "crate_naming",
                include_str!("../../../../bifrost-rust/src/crate_naming.rs"),
            ),
            (
                "diagnostics",
                include_str!("../../../../bifrost-rust/src/diagnostics.rs"),
            ),
            (
                "field_roles",
                include_str!("../../../../bifrost-rust/src/field_roles.rs"),
            ),
            (
                "format_args",
                include_str!("../../../../bifrost-rust/src/format_args.rs"),
            ),
            (
                "binding_identity",
                include_str!("../../../../bifrost-rust/src/binding_identity.rs"),
            ),
        ];
        let mut project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"real\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "src/lib.rs",
                SOURCES
                    .iter()
                    .map(|(name, _)| format!("pub mod {name};\n"))
                    .collect::<String>(),
            );
        for (name, text) in SOURCES {
            project = project.file(format!("src/{name}.rs"), *text);
        }
        let project = project.build();
        let workspace = project.certified_workspace_analyzer(Default::default());
        let analyzer = brokk_bifrost_analysis::analyzer::resolve_analyzer::<RustAnalyzer>(
            workspace.analyzer(),
        )
        .unwrap();
        let store = workspace.store().unwrap();
        store.execute_selection_publication(|conn| {
            let _fixture =
                brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(conn);
            conn.execute(
                "UPDATE rust_resolution_unit_summary_contexts SET broad_complete=0",
                [],
            )
            .unwrap();
            for (name, _) in SOURCES {
                conn.execute(
                    "INSERT INTO rust_resolution_unit_summary_gaps(summary_id,gap_kind,subject,detail) SELECT summary_id,'unknown_activation',?1,jsonb(?2) FROM rust_resolution_unit_summary_contexts",
                    rusqlite::params![
                        format!("crate::{name}"),
                        serde_json::json!({"path": format!("src/{name}.rs")}).to_string()
                    ],
                )
                .unwrap();
            }
        });
        let scope = AnalyzerQueryScope::new(analyzer);
        let mut open_files = 0;
        with_usage_read_frame(analyzer, || {
            capture(analyzer, &mut || {}).expect("pin reader before cache capture");
            for (name, _) in SOURCES {
                let file = project.file(format!("src/{name}.rs"));
                let lookup = || {
                    let walks = RustUsageWalks::new(analyzer, scope.token()).unwrap();
                    walks.origin_routes_of(&file).unwrap()
                };
                let mut fresh = (vec![], [0u8; 32]);
                let cold = capture(analyzer, &mut || {
                    drop(lookup());
                })
                .unwrap();
                cold.receipt().collect_causes(&mut fresh.0);
                fresh.1 = cold.digest();
                let hit = capture(analyzer, &mut || {
                    drop(lookup());
                })
                .unwrap();
                let mut replayed = vec![];
                hit.receipt().collect_causes(&mut replayed);
                let mut sorted = replayed.clone();
                sorted.sort();
                sorted.dedup();
                let mut fresh_sorted = fresh.0.clone();
                fresh_sorted.sort();
                fresh_sorted.dedup();
                assert_eq!(sorted, fresh_sorted, "{name}: replayed cause set");
                assert_eq!(hit.digest(), fresh.1, "{name}: replayed digest");
                assert_eq!(
                    hit.digest(),
                    walk_completion_digest(replayed),
                    "{name}: digest equals the v1 reference over the full set"
                );
                open_files += usize::from(hit.is_open());
            }
        });
        assert!(open_files > 0, "the workload must exercise Open fills");
    }
}
