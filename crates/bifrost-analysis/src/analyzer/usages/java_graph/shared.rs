use super::{
    build_java_edges, build_java_file_cache_evidence, build_java_file_usage_evidence,
    merge_java_cached_file_evidence, merge_java_file_evidence,
};
use crate::analyzer::content_identity::WorkspaceContentIdentity;
use crate::analyzer::semantic::StableDigest;
use crate::analyzer::usages::common::language_for_file;
use crate::analyzer::usages::inverted_edges::EdgeNodeDomain;
use crate::analyzer::usages::inverted_edges::{UsageEdgeWeights, UsageEdges};
use crate::analyzer::usages::java_usage_evidence_cache::{
    JavaUsageEvidenceCacheAcquisition, JavaUsageEvidenceCacheKey,
    JavaUsageEvidenceSemanticModelIdentity, JavaUsageEvidenceTargetKey,
};
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageQueryResolver, UsageScanScope};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::analyzer::{
    BulkFileStateSource, CodeUnit, IAnalyzer, JavaAnalyzer, Language, ProjectFile, resolve_analyzer,
};
use crate::hash::HashSet;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_jvm::java::graph::extractor::OwnedReturnTypeCaches;
use brokk_bifrost_jvm::java::graph::extractor::{JavaFileEvidenceBuildOutcome, ScanState};
use std::collections::BTreeSet;

pub(crate) struct JavaQueryResolver<'a> {
    java: &'a JavaAnalyzer,
}

fn java_target_spec_fingerprint(
    spec: &brokk_bifrost_jvm::java::graph::resolver::TargetSpec,
) -> StableDigest {
    let mut hasher = CanonicalHasher::new(b"bifrost-java-usage-evidence:target-spec:v1");
    let kind = match spec.kind {
        brokk_bifrost_jvm::java::graph::resolver::TargetKind::Type => "type",
        brokk_bifrost_jvm::java::graph::resolver::TargetKind::Constructor => "constructor",
        brokk_bifrost_jvm::java::graph::resolver::TargetKind::Method => "method",
        brokk_bifrost_jvm::java::graph::resolver::TargetKind::Field => "field",
    };
    hasher.field("kind", kind.as_bytes());
    hasher.field("owner", spec.owner.declaration_id().as_str().as_bytes());
    hasher.field("member", spec.member_name.as_bytes());

    let mut receiver_owners = spec.receiver_owner_fq_names.iter().collect::<Vec<_>>();
    receiver_owners.sort_unstable();
    hasher.sequence("receiver-owners", &receiver_owners, |digest, owner| {
        digest.value(owner.as_bytes());
    });

    let mut arities = spec
        .callable_arities
        .as_ref()
        .map(|values| {
            values
                .iter()
                .map(|arity| (arity.required(), arity.total(), arity.is_repeated()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    arities.sort_unstable();
    hasher.sequence(
        "callable-arities",
        &arities,
        |digest, (required, total, repeated)| {
            digest.value(&required.to_be_bytes());
            digest.value(&total.to_be_bytes());
            digest.value(&[*repeated as u8]);
        },
    );
    StableDigest::from_array(hasher.finish())
}

fn java_resolution_policy_fingerprint(analyzer: &dyn IAnalyzer) -> Option<StableDigest> {
    let external_dispatch = analyzer.external_dispatch_behavior_identity()?;
    let mut hasher = CanonicalHasher::new(b"bifrost-java-usage-evidence:resolution-policy:v1");
    hasher.field("external-dispatch", external_dispatch.as_bytes());
    hasher.field("java-graph-representation", b"exact-uncapped-v1");
    Some(StableDigest::from_array(hasher.finish()))
}

fn java_evidence_cache_key(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    overloads: &[CodeUnit],
    spec: &brokk_bifrost_jvm::java::graph::resolver::TargetSpec,
) -> Option<(JavaUsageEvidenceCacheKey, WorkspaceContentIdentity)> {
    let content = analyzer.workspace_content_identity()?;
    let policy = java_resolution_policy_fingerprint(analyzer)?;
    let semantic_model_identity = analyzer
        .active_semantic_model_snapshot()
        .map(|snapshot| {
            JavaUsageEvidenceSemanticModelIdentity::ActiveModelSet(StableDigest::sha256(
                snapshot.active_models().active_model_set_hash().as_bytes(),
            ))
        })
        .unwrap_or(JavaUsageEvidenceSemanticModelIdentity::None);
    let target =
        JavaUsageEvidenceTargetKey::from_targets(overloads, java_target_spec_fingerprint(spec));
    Some((
        JavaUsageEvidenceCacheKey::new(
            content,
            file.clone(),
            target,
            semantic_model_identity,
            policy,
        ),
        content,
    ))
}

impl<'a> UsageQueryResolver<'a> for JavaQueryResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            java: resolve_analyzer::<JavaAnalyzer>(analyzer)?,
        })
    }

    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let Some(target) = overloads.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        let uncancelled = crate::CancellationToken::new();
        let cancellation = scan_scope.cancellation().unwrap_or(&uncancelled);
        let target_spec_scope = crate::profiling::scope("java_graph::target_spec");
        let Some(spec) = brokk_bifrost_jvm::java::graph::resolver::TargetSpec::from_targets(
            self.java, overloads,
        ) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                "JavaUsageGraphStrategy",
            );
        };
        drop(target_spec_scope);

        let select_files_scope = crate::profiling::scope("java_graph::select_files");
        let candidate_files = scan_scope.candidate_files();
        let mut files: Vec<ProjectFile> = candidate_files
            .iter()
            .filter(|file| language_for_file(file) == Language::Java)
            .cloned()
            .collect();
        if scan_scope.allows(target.source()) {
            files.push(target.source().clone());
        }
        files.sort();
        files.dedup();
        drop(select_files_scope);
        let mut hits: BTreeSet<UsageHit> = BTreeSet::new();
        let mut unproven_hits: BTreeSet<UsageHit> = BTreeSet::new();
        let mut raw_match_count = 0usize;
        let mut limit_exceeded = false;
        let mut state = ScanState {
            max_usages,
            hits: &mut hits,
            unproven_hits: &mut unproven_hits,
            raw_match_count: &mut raw_match_count,
            limit_exceeded: &mut limit_exceeded,
        };
        let mut relational_session = None;
        let return_caches = OwnedReturnTypeCaches::default();
        for file in &files {
            let _scan_scope = crate::profiling::scope("java_graph::scan_file");
            let cache_key = java_evidence_cache_key(analyzer, file, overloads, &spec);
            if let (Some(caches), Some((key, content))) = (analyzer.snapshot_caches(), cache_key) {
                match caches.java_usage_evidence().acquire(
                    key,
                    cancellation,
                    || {
                        let relational_session = relational_session.get_or_insert_with(|| {
                            crate::analyzer::relational_frontier::RelationalFrontierSession::new(
                                analyzer,
                                cancellation,
                            )
                        });
                        let evidence = build_java_file_cache_evidence(
                            relational_session,
                            analyzer,
                            self.java,
                            token,
                            file,
                            &spec,
                            &return_caches,
                            cancellation,
                        );
                        match evidence {
                            crate::analyzer::usages::java_usage_evidence_cache::JavaUsageEvidenceBuildOutcome::Complete(_)
                                if scope.store_error().is_some() =>
                            {
                                crate::analyzer::usages::java_usage_evidence_cache::JavaUsageEvidenceBuildOutcome::Omitted(
                                    crate::analyzer::usages::java_usage_evidence_cache::JavaUsageEvidenceOmission::StoreProvider,
                                )
                            }
                            evidence => evidence,
                        }
                    },
                    || analyzer.workspace_content_matches(content),
                ) {
                    JavaUsageEvidenceCacheAcquisition::Ready {
                        evidence,
                        lifecycle,
                        wait,
                    } => {
                        crate::profiling::note_with(|| {
                            format!(
                                "java usage evidence {:?}; waits={} wait_ns={}",
                                lifecycle, wait.waits, wait.wait_ns
                            )
                        });
                        merge_java_cached_file_evidence(&evidence, &mut state);
                    }
                    JavaUsageEvidenceCacheAcquisition::Omitted(reason) => {
                        crate::profiling::note_with(|| {
                            format!("Java file evidence omitted for {:?}: {reason:?}", file)
                        });
                        return GraphUsageOutcome::fallback_safe(
                            target.fq_name(),
                            GraphFailureReason::MissingAnalyzerCapability(
                                "a Java file has no complete semantic evidence",
                            ),
                            "JavaUsageGraphStrategy",
                        );
                    }
                    JavaUsageEvidenceCacheAcquisition::Cancelled => break,
                    JavaUsageEvidenceCacheAcquisition::Stale => {
                        crate::profiling::note_with(|| {
                            format!("Java file evidence became stale for {:?}", file)
                        });
                        return GraphUsageOutcome::fallback_safe(
                            target.fq_name(),
                            GraphFailureReason::MissingAnalyzerCapability(
                                "a Java file evidence snapshot became stale",
                            ),
                            "JavaUsageGraphStrategy",
                        );
                    }
                }
            } else {
                // Without an attested cache owner/key, run the same exact
                // uncapped producer locally. Keep one frontier for all misses.
                let relational_session = relational_session.get_or_insert_with(|| {
                    crate::analyzer::relational_frontier::RelationalFrontierSession::new(
                        analyzer,
                        cancellation,
                    )
                });
                let evidence = build_java_file_usage_evidence(
                    relational_session,
                    analyzer,
                    self.java,
                    token,
                    file,
                    &spec,
                    &return_caches,
                    cancellation,
                );
                match evidence {
                    JavaFileEvidenceBuildOutcome::Complete(evidence) => {
                        if scope.store_error().is_some() {
                            return GraphUsageOutcome::fallback_safe(
                                target.fq_name(),
                                GraphFailureReason::MissingAnalyzerCapability(
                                    "a Java evidence build observed a store failure",
                                ),
                                "JavaUsageGraphStrategy",
                            );
                        }
                        merge_java_file_evidence(evidence, &mut state);
                    }
                    JavaFileEvidenceBuildOutcome::Cancelled => break,
                    JavaFileEvidenceBuildOutcome::Omitted(reason) => {
                        crate::profiling::note_with(|| {
                            format!("Java file evidence omitted for {:?}: {reason:?}", file)
                        });
                        return GraphUsageOutcome::fallback_safe(
                            target.fq_name(),
                            GraphFailureReason::MissingAnalyzerCapability(
                                "a Java file has no complete semantic evidence",
                            ),
                            "JavaUsageGraphStrategy",
                        );
                    }
                }
            }
            if *state.limit_exceeded {
                break;
            }
        }
        let _scala_scope = crate::profiling::scope("java_graph::scan_scala_files");
        super::scan_scala_files_for_java_target(analyzer, candidate_files, &spec, &mut state, None);
        drop(_scala_scope);
        // A Java class is equally nameable from Kotlin source; the realm is one
        // candidate space, so find-references on a Java type must see its Kotlin
        // call sites too (#1239 milestone 4).
        let _kotlin_scope = crate::profiling::scope("java_graph::scan_kotlin_files");
        crate::analyzer::usages::kotlin_graph::scan_kotlin_files_for_jvm_type(
            analyzer,
            candidate_files,
            target,
            max_usages,
            state.hits,
            state.unproven_hits,
            state.raw_match_count,
            state.limit_exceeded,
        );
        drop(_kotlin_scope);

        let external_callsites = crate::analyzer::usages::common::external_usage_hit_count(&hits);
        if limit_exceeded || external_callsites > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: target.short_name().to_string(),
                total_callsites: external_callsites,
                limit: max_usages,
                sample_hits: hits,
            });
        }

        GraphUsageOutcome::Resolved(FuzzyResult::success_with_unproven(
            target.clone(),
            hits,
            unproven_hits,
        ))
    }
}

pub(crate) struct JavaEdgeResolver<'a> {
    java: &'a JavaAnalyzer,
    files: Vec<ProjectFile>,
}

/// The whole-workspace `caller -> callee` scan behind this language's
/// [`LanguageEdgePass`](crate::analyzer::languages::LanguageEdgePass): borrow the concrete
/// analyzer once, then walk every file once and finalize into either site-bearing edges or
/// reference-kind weights.
impl<'a> JavaEdgeResolver<'a> {
    pub(crate) fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let java = resolve_analyzer::<JavaAnalyzer>(analyzer)?;
        let files: Vec<ProjectFile> = analyzer
            .project()
            .analyzable_files(Language::Java)
            .ok()?
            .into_iter()
            .collect();
        Some(Self { java, files })
    }

    pub(crate) fn build_edges<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdges
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        let selected_files: Vec<_> = self
            .files
            .iter()
            .filter(|file| keep_file(file))
            .cloned()
            .collect();
        let file_states = self
            .java
            .bulk_file_states(selected_files, BulkFileStateSource::Omit);
        build_java_edges(
            analyzer,
            self.java,
            &self.files,
            &file_states,
            EdgeNodeDomain::Closed(nodes),
            keep_file,
        )
    }

    pub(crate) fn build_rooted_edges<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        callers: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdges
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        let selected_files: Vec<_> = self
            .files
            .iter()
            .filter(|file| keep_file(file))
            .cloned()
            .collect();
        let file_states = self
            .java
            .bulk_file_states(selected_files, BulkFileStateSource::Omit);
        build_java_edges(
            analyzer,
            self.java,
            &self.files,
            &file_states,
            EdgeNodeDomain::Rooted(callers),
            keep_file,
        )
    }

    pub(crate) fn build_edge_weights<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdgeWeights
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        let selected_files: Vec<_> = self
            .files
            .iter()
            .filter(|file| keep_file(file))
            .cloned()
            .collect();
        let file_states = self
            .java
            .bulk_file_states(selected_files, BulkFileStateSource::Omit);
        build_java_edges(
            analyzer,
            self.java,
            &self.files,
            &file_states,
            EdgeNodeDomain::Closed(nodes),
            keep_file,
        )
    }
}
