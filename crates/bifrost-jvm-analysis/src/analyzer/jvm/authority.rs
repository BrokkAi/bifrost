//! Every primitive JVM authority accessor crosses a named recording funnel.
//! Scope-tier answers include the entire JVM source realm; dependency-backed
//! answers additionally name manifests and negative build-file probes.
use brokk_bifrost_analysis::analyzer::workspace_authority::{
    AuthorityInputs, record_workspace_authority_read, workspace_authority_file_input,
};
use brokk_bifrost_analysis::analyzer::{
    FactSubject, IAnalyzer, ReadKey, WorkspaceFactFamily, capture_query_reads,
};
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::model::Language;
use brokk_bifrost_jvm::proof::JvmRetainedExternalIndex;

pub(crate) fn source_read(analyzer: &dyn IAnalyzer, family: WorkspaceFactFamily) {
    record_workspace_authority_read(
        analyzer,
        family,
        AuthorityInputs::SourceOf(&[Language::Java, Language::Kotlin, Language::Scala]),
    );
}

/// What the carry compares: a fixed-size digest of the recorded input keys
/// (the tree inputs and the artifact fact), not the keys themselves, so a filled
/// slot retains a few dozen bytes however many keys the receipt names.
type JvmCarrySample = [u8; 32];

type ExternalFill = brokk_bifrost_analysis::analyzer::external_carry::ExternalFill<
    std::sync::Arc<super::external::JvmExternalDeclarationIndex>,
    JvmCarrySample,
>;

type ExternalCarry = brokk_bifrost_analysis::analyzer::external_carry::ExternalCarry<
    std::sync::Arc<super::external::JvmExternalDeclarationIndex>,
    JvmCarrySample,
>;

type ExternalIndexCell = brokk_bifrost_analysis::analyzer::common::QueryCacheCell<
    brokk_bifrost_analysis::analyzer::common::ReplayableQueryCacheValue<
        std::sync::Arc<ExternalFill>,
    >,
>;

/// One JVM analyzer's external declaration index together with the bounded
/// receipt of the inputs its build read. Java, Kotlin and Scala each hold one.
///
/// The slot is unbuilt until a first read fills it, which inserts the receipt
/// in the same step. A new analyzer generation never shares its predecessor's
/// cell. [`Self::updated`] hands the predecessor's fill to the new slot as a
/// candidate, and the first read of the new generation decides, in the cell's
/// single fill, whether the candidate still holds: it samples the dependency
/// inputs at the new generation and carries the index only when they equal the
/// inputs the candidate recorded (see [`record_external_inputs`]). Either way
/// the fill records a receipt of the new generation, so a carried index is
/// attributed exactly like a rebuilt one. A cancelled or refused fill leaves the
/// candidate in place for the next reader.
///
/// A built index can still outlive its receipt: the bounded receipt memo evicts
/// it. A read of an index without its receipt never samples new inputs for the
/// old value: it records an unattributed read, which refuses certification.
/// Eviction is the memo's, so the receipt state is observed on each read, not
/// stored.
#[derive(Clone)]
pub(crate) struct JvmExternalIndexSlot {
    index: std::sync::Arc<std::sync::RwLock<std::sync::Arc<ExternalIndexCell>>>,
    receipt: super::hierarchy::RawDerivedMemo<(), ()>,
    carry: ExternalCarry,
}

impl JvmExternalIndexSlot {
    pub(crate) fn new(memo_budget: u64) -> Self {
        Self::with_carry(memo_budget, ExternalCarry::default())
    }

    fn with_carry(memo_budget: u64, carry: ExternalCarry) -> Self {
        Self {
            index: std::sync::Arc::new(std::sync::RwLock::new(std::sync::Arc::new(
                ExternalIndexCell::new(),
            ))),
            receipt: super::hierarchy::raw_derived_memo(memo_budget / 8),
            carry,
        }
    }

    /// The slot of the next analyzer generation: an empty cell that may carry
    /// this slot's index if the first read finds its inputs unchanged.
    pub(crate) fn updated(&self, memo_budget: u64) -> Self {
        let cell = self.index.read().unwrap();
        let filled = cell.get().map(|entry| entry.value());
        Self::with_carry(memo_budget, self.carry.successor(filled))
    }

    /// Whether a fill has completed. A slot whose predecessor's index awaits
    /// its first read is not built. Records no read.
    pub(crate) fn is_built(&self) -> bool {
        self.index.read().unwrap().get().is_some()
    }

    #[cfg(test)]
    pub(crate) fn shares_index_with(&self, other: &Self) -> bool {
        match (
            self.index.read().unwrap().get(),
            other.index.read().unwrap().get(),
        ) {
            (Some(left), Some(right)) => {
                std::sync::Arc::ptr_eq(left.value().value(), right.value().value())
            }
            _ => false,
        }
    }

    /// The built index, read through its receipt, without building it.
    pub(crate) fn retained(
        &self,
        analyzer: &dyn IAnalyzer,
    ) -> Option<std::sync::Arc<super::external::JvmExternalDeclarationIndex>> {
        self.record_read(analyzer);
        self.index
            .read()
            .unwrap()
            .get()
            .map(|entry| std::sync::Arc::clone(entry.replay().value()))
    }

    /// Classify the retained index for the proof-gated diagnostic ladder.
    pub(crate) fn retained_state(&self, analyzer: &dyn IAnalyzer) -> JvmRetainedExternalIndex {
        super::retained_external_index_state(self.retained(analyzer).as_deref())
    }

    /// Record the read of a built index through its receipt. Reading an
    /// unbuilt slot consumes no external index and records nothing, except
    /// that a slot still holding a predecessor's index has not yet decided
    /// whether that index applies: that read is unattributed.
    pub(crate) fn record_read(&self, analyzer: &dyn IAnalyzer) {
        if !self.is_built() {
            if self.carry.pending().is_some() {
                analyzer.record_unattributed_read();
            }
            return;
        }
        self.receipt
            .read(
                &brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(analyzer),
                |cache, capture| {
                    Ok::<_, std::convert::Infallible>(cache.get(&()).unwrap_or_else(|| {
                        std::sync::Arc::new(capture.build(|| {
                            analyzer.record_unattributed_read();
                            std::sync::Arc::new(())
                        }))
                    }))
                },
            )
            .expect("external receipt lookup is infallible");
        if let Some(entry) = self.index.read().unwrap().get() {
            super::external::QueryGapRecorder::new(analyzer)
                .whole_index(entry.replay().value().as_ref());
        }
    }

    pub(crate) fn invalidate_inventory_generation(&self, generation: i64) {
        let mut cell = self.index.write().unwrap();
        if cell
            .get()
            .is_some_and(|entry| entry.value().value().inventory_generation != Some(generation))
        {
            // The generation is global, so each first-bind publication of a
            // provider discards every retained JVM external-index cell once.
            // Publications happen once per provider per store; this is accepted.
            *cell = std::sync::Arc::new(ExternalIndexCell::new());
        }
        if self
            .carry
            .pending()
            .is_some_and(|candidate| candidate.value().inventory_generation != Some(generation))
        {
            self.carry.settle();
        }
    }

    /// The index, built by `build` on first use unless the predecessor's index
    /// still holds. The fill records the external inputs under `authority` into
    /// the receipt it inserts.
    pub(crate) fn get_or_build(
        &self,
        analyzer: &dyn IAnalyzer,
        authority: (Language, WorkspaceFactFamily),
        sample_artifacts: impl Fn() -> (
            brokk_bifrost_analysis::analyzer::semantic::StableDigest,
            bool,
            [u8; 32],
        ),
        verify_artifacts: impl FnOnce() -> (
            brokk_bifrost_analysis::analyzer::semantic::StableDigest,
            bool,
            [u8; 32],
        ),
        record_carried: impl FnOnce(&super::external::JvmExternalDeclarationIndex),
        build: impl FnOnce() -> std::sync::Arc<super::external::JvmExternalDeclarationIndex>,
    ) -> std::sync::Arc<super::external::JvmExternalDeclarationIndex> {
        // Keep replacement behind this read guard until the winning receipt
        // has been installed, so an older fill cannot overwrite a newer receipt.
        let cell = self.index.read().unwrap();
        let index = &**cell;
        let mut result = None;
        self.receipt
            .read(
                &brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(analyzer),
                |cache, capture| {
                    let mut built = None;
                    let value =
                        brokk_bifrost_analysis::analyzer::common::replayable_query_cache_cell(
                            analyzer,
                            index,
                            || {
                                let mut value = None;
                                let receipt = std::sync::Arc::new(capture.build_weighted(|| {
                                    // Name the initial sample in the receipt whether
                                    // the predecessor index is carried or rebuilt.
                                    let (artifact_sample, sample) = capture_query_reads(analyzer, || {
                                        record_external_inputs(
                                            analyzer,
                                            authority.0,
                                            authority.1,
                                            &sample_artifacts,
                                        )
                                    });
                                    let mut carry = CanonicalHasher::new(b"bifrost-jvm-carry-with-stat:v1");
                                    carry.field("reads", &carry_sample_digest(&sample.keys()));
                                    carry.field("stat", &artifact_sample.2);
                                    let inputs = carry.finish();
                                    // The build's own project reads are not recorded a
                                    // second time: recording them would make a
                                    // rebuilt receipt differ from a carried one.
                                    let fill = self.carry.resolve(inputs, sample.is_bounded(), || {
                                        brokk_bifrost_analysis::analyzer::external_carry::build_with_verified_inputs(
                                            &artifact_sample,
                                            build,
                                            || {
                                                let after = verify_artifacts();
                                                after.1.then_some(after)
                                            },
                                        ).into_value(analyzer)
                                    });
                                    // A carried index did not run the build that records
                                    // the inventory it was decoded with; record it so the
                                    // carried receipt names what a rebuilt one does.
                                    if self.carry.pending().is_some_and(|candidate| {
                                        std::sync::Arc::ptr_eq(&candidate, &fill)
                                    }) {
                                        record_carried(fill.value().as_ref());
                                    }
                                    // Vacuous for a carried index: it names the
                                    // retained index's own gaps. What decides the
                                    // carry is the artifact sample above.
                                    record_workspace_authority_read(
                                        analyzer,
                                        WorkspaceFactFamily::JvmExternalGaps,
                                        AuthorityInputs::Fact {
                                            language: Language::None,
                                            subject: FactSubject::Whole,
                                            answer: fill.value().gap_identity(),
                                        },
                                    );
                                    value = Some(fill);
                                    (std::sync::Arc::new(()), 0)
                                }));
                                let value = value.expect("builder produced an index");
                                built = Some((std::sync::Arc::clone(&value), receipt));
                                value
                            },
                        );
                    let retained = index
                        .get()
                        .is_some_and(|retained| std::sync::Arc::ptr_eq(retained, &value));
                    if retained {
                        // The decision is made; the predecessor's index is no
                        // longer a candidate, and its memory can go.
                        self.carry.settle();
                    }
                    if retained
                        && let Some((built_value, receipt)) = &built
                        && std::sync::Arc::ptr_eq(built_value, &value)
                    {
                        cache.insert((), std::sync::Arc::clone(receipt));
                    }
                    result = Some(std::sync::Arc::clone(value.value()));
                    let receipt = if retained {
                        cache.get(&())
                    } else {
                        built.map(|(_, receipt)| receipt)
                    };
                    Ok::<_, std::convert::Infallible>(receipt.unwrap_or_else(|| {
                        std::sync::Arc::new(capture.build(|| {
                            // A winning index whose bounded receipt was evicted
                            // cannot be certified from freshly sampled inputs.
                            analyzer.record_unattributed_read();
                            std::sync::Arc::new(())
                        }))
                    }))
                },
            )
            .expect("external index initialization is infallible");
        result.expect("external lookup produced an owned index")
    }
}

/// The visible JVM dependency inputs of the analyzer's workspace (#12745): the
/// files of the listing, after ignore rules and overlays, that
/// [`is_jvm_dependency_input`] accepts. Artifacts are covered by the content
/// digests of `JvmArtifactInputs`.
pub(crate) struct VisibleDependencyInputs {
    manifests: Vec<brokk_bifrost_core::analyzer::model::ProjectFile>,
    answer: brokk_bifrost_analysis::analyzer::semantic::StableDigest,
}

pub(crate) fn visible_dependency_inputs(
    analyzer: &dyn IAnalyzer,
) -> std::io::Result<VisibleDependencyInputs> {
    use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
    // The generation's own listing, the view the build reads (#12745).
    let generation =
        brokk_bifrost_analysis::analyzer::workspace::generation_dependency_discovery_project(
            analyzer,
        );
    let files = brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
        generation.all_files()
    })?;
    let mut manifests = Vec::new();
    // Only the visible manifests' paths: they detect an ignore-rule or overlay
    // change that shows or hides one. Artifact identity is the content digests
    // of `JvmArtifactInputs`, never a stat identity (#13404).
    let mut entries = Vec::new();
    for file in files {
        if super::dependency_discovery::is_jvm_dependency_input(&file) {
            entries.push(
                brokk_bifrost_analysis::path_utils::workspace_relative_slash_path(file.rel_path()),
            );
            manifests.push(file);
        }
    }
    entries.sort_unstable();
    let mut hash = CanonicalHasher::new(b"bifrost-jvm-dependency-inputs:v3");
    hash.sequence("paths", &entries, |hash, path| {
        hash.field("rel_path", path.as_bytes());
    });
    Ok(VisibleDependencyInputs {
        manifests,
        answer: brokk_bifrost_analysis::analyzer::semantic::StableDigest::from_array(hash.finish()),
    })
}

/// The answer to the `JvmDependencyInputs` fact at the analyzer's generation.
pub(crate) fn visible_dependency_inputs_answer(
    analyzer: &dyn IAnalyzer,
) -> Option<brokk_bifrost_analysis::analyzer::semantic::StableDigest> {
    visible_dependency_inputs(analyzer)
        .ok()
        .map(|visible| visible.answer)
}

/// The answer to the `JvmArtifactInputs` fact at the analyzer's generation.
/// `None` when the sample is not reusable, which invalidates the recorded key.
pub(crate) fn artifact_inputs_answer(
    analyzer: &dyn IAnalyzer,
) -> Option<brokk_bifrost_analysis::analyzer::semantic::StableDigest> {
    let config = crate::analyzer::java::jvm_analyzer_config(analyzer)?;
    let project =
        brokk_bifrost_analysis::analyzer::workspace::generation_dependency_discovery_project(
            analyzer,
        );
    let (digest, reusable, _) =
        brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
            super::external::dependency_discovery_sample(analyzer, config, project.as_ref())
        });
    reusable.then_some(digest)
}

/// A fixed-size digest of the recorded input keys, without the source-realm
/// `Scope` key (it changes on every source edit and is not an index input).
fn carry_sample_digest(keys: &[ReadKey]) -> JvmCarrySample {
    use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
    let keys: Vec<_> = keys
        .iter()
        .filter(|key| !matches!(key, ReadKey::Scope { .. }))
        .collect();
    let mut hash = CanonicalHasher::new(b"bifrost-jvm-external-carry-sample:v1");
    hash.sequence("keys", &keys, |hash, key| {
        hash.field("key", key.canonical_digest().as_bytes())
    });
    hash.finish()
}

/// Name every tree input that a JVM external index build reads: the visible
/// dependency inputs as one fact, the content of each visible manifest, and the
/// absence of each conventional manifest path. A manifest that appears,
/// disappears or changes, and an ignore-rule or overlay change that shows or
/// hides one, all change a recorded key.
fn record_external_inputs(
    analyzer: &dyn IAnalyzer,
    language: Language,
    family: WorkspaceFactFamily,
    sample_artifacts: impl Fn() -> (
        brokk_bifrost_analysis::analyzer::semantic::StableDigest,
        bool,
        [u8; 32],
    ),
) -> (
    brokk_bifrost_analysis::analyzer::semantic::StableDigest,
    bool,
    [u8; 32],
) {
    let visible = match visible_dependency_inputs(analyzer) {
        Ok(visible) => visible,
        Err(error) => {
            analyzer.record_query_failure(
                brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                    "JVM dependency inventory IO: {error}"
                )),
            );
            return (
                brokk_bifrost_analysis::analyzer::semantic::StableDigest::from_array([0; 32]),
                false,
                [0; 32],
            );
        }
    };
    record_workspace_authority_read(
        analyzer,
        WorkspaceFactFamily::JvmDependencyInputs,
        AuthorityInputs::Fact {
            language: Language::None,
            subject: FactSubject::Whole,
            answer: visible.answer,
        },
    );
    // The jars the index decodes, wherever they live, and the scan that found
    // them: a verifiable fact, recomputed on replay by the same sampler. An
    // unreadable artifact or probe, or an incomplete discovery, is not a fact:
    // the read is unattributed and the receipt is unbounded.
    let (artifacts, artifacts_reusable, stat_sample) =
        brokk_bifrost_core::analyzer::project_reads::without_project_reads(sample_artifacts);
    if artifacts_reusable {
        record_workspace_authority_read(
            analyzer,
            WorkspaceFactFamily::JvmArtifactInputs,
            AuthorityInputs::Fact {
                language: Language::None,
                subject: FactSubject::Whole,
                answer: artifacts,
            },
        );
    } else {
        analyzer.record_unattributed_read();
        analyzer.refuse_read_reuse();
    }
    let mut paths = visible
        .manifests
        .iter()
        .map(|file| file.rel_path().to_path_buf())
        .collect::<Vec<_>>();
    paths.extend(
        [
            "pom.xml",
            "settings.xml",
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
            "gradle.properties",
            "gradle.lockfile",
            "gradle/libs.versions.toml",
            "gradle/wrapper/gradle-wrapper.properties",
            ".mvn/maven.config",
            ".mvn/jvm.config",
            ".mvn/extensions.xml",
            ".mvn/wrapper/maven-wrapper.properties",
        ]
        .map(std::path::PathBuf::from),
    );
    paths.sort();
    paths.dedup();
    let keys = paths
        .iter()
        .filter_map(|path| {
            let key = workspace_authority_file_input(
                analyzer,
                language,
                &brokk_bifrost_analysis::path_utils::workspace_relative_slash_path(path),
            );
            if key.is_none() {
                analyzer.record_unattributed_read();
            }
            key
        })
        .collect::<Vec<_>>();
    record_workspace_authority_read(
        analyzer,
        family,
        AuthorityInputs::SourceAndFiles {
            languages: &[Language::Java, Language::Kotlin, Language::Scala],
            files: keys.into(),
        },
    );
    (artifacts, artifacts_reusable, stat_sample)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::{
        AnalyzerConfig, ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers, ReadKey,
        ReadVerdict, capture_query_reads,
    };

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#8148: a binary .mvn/wrapper/maven-wrapper.jar authority input refused every JVM external index fill"
    )]
    fn binary_wrapper_inputs_retain_external_index_and_properties_invalidate() {
        let project = InlineTestProject::with_language(Language::Java)
            .file("App.java", "class App {}")
            .file("pom.xml", "<project/>")
            .file(".mvn/wrapper/maven-wrapper.jar", "PK\0\0")
            .file("buildSrc/resource.bin", "binary\0resource")
            .file(
                ".mvn/wrapper/maven-wrapper.properties",
                "distributionUrl=first",
            )
            .build();
        for path in [".mvn/wrapper/maven-wrapper.jar", "buildSrc/resource.bin"] {
            std::fs::write(project.file(path).abs_path(), b"PK\0\xff").unwrap();
        }
        let base = project.workspace_analyzer(AnalyzerConfig::default());
        let java = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
            crate::analyzer::java::JavaAnalyzer,
        >(base.analyzer())
        .unwrap();
        let (first, reads) =
            capture_query_reads(base.analyzer(), || java.external_declaration_index());
        let (second, warm) =
            capture_query_reads(base.analyzer(), || java.external_declaration_index());
        assert!(
            std::sync::Arc::ptr_eq(&first, &second),
            "external index rebuilt"
        );
        assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
        assert_eq!(warm.unattributed_reads(), 0, "{warm:?}");
        assert_eq!(reads.keys(), warm.keys());
        assert!(
            warm.keys()
                .iter()
                .any(|key| matches!(key, ReadKey::File { rel_path, .. }
            if rel_path.as_ref() == "buildSrc/resource.bin")),
            "{warm:?}"
        );
        assert!(
            !warm
                .keys()
                .iter()
                .any(|key| matches!(key, ReadKey::File { rel_path, .. }
            if rel_path.as_ref() == ".mvn/wrapper/maven-wrapper.jar")),
            "{warm:?}"
        );
        let verify = |head: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer| {
            brokk_bifrost_analysis::analyzer::read_verification::verify_read_set(
                head,
                &ChangedFacts::between(&base, head),
                &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
                &warm.keys(),
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::new(),
            )
        };
        assert_eq!(verify(&base), ReadVerdict::Unchanged);
        project
            .file(".mvn/wrapper/maven-wrapper.properties")
            .write("distributionUrl=second")
            .unwrap();
        let edited = project.workspace_analyzer(AnalyzerConfig::default());
        assert_ne!(verify(&edited), ReadVerdict::Unchanged);
    }

    const VERSIONED_POM: &str = "<project><dependencies><dependency><groupId>com.example</groupId><artifactId>missing-lib</artifactId><version>1.2.3</version></dependency></dependencies></project>";

    fn jvm_source(language: Language) -> (&'static str, &'static str) {
        match language {
            Language::Java => ("App.java", "class App {}"),
            Language::Kotlin => ("App.kt", "class App"),
            Language::Scala => ("App.scala", "class App"),
            _ => unreachable!(),
        }
    }

    fn external_index_of(
        workspace: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        language: Language,
    ) -> std::sync::Arc<super::super::external::JvmExternalDeclarationIndex> {
        use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
        let analyzer = workspace.analyzer();
        match language {
            Language::Java => resolve_analyzer::<crate::analyzer::java::JavaAnalyzer>(analyzer)
                .unwrap()
                .external_declaration_index(),
            Language::Kotlin => {
                resolve_analyzer::<crate::analyzer::kotlin::KotlinAnalyzer>(analyzer)
                    .unwrap()
                    .external_declaration_index()
            }
            Language::Scala => resolve_analyzer::<crate::analyzer::scala::ScalaAnalyzer>(analyzer)
                .unwrap()
                .external_declaration_index(),
            _ => unreachable!(),
        }
    }

    /// Assert that `updated` answers like a from-scratch analyzer over the same
    /// tree: same gaps and same dispatch behavior.
    fn assert_equals_from_scratch(
        project: &crate::inline_project::BuiltInlineTestProject,
        updated: &std::sync::Arc<super::super::external::JvmExternalDeclarationIndex>,
        language: Language,
        config: AnalyzerConfig,
    ) {
        let scratch = project.workspace_analyzer(config);
        let scratch = external_index_of(&scratch, language);
        assert_eq!(
            updated.gap_identity(),
            scratch.gap_identity(),
            "{language:?}"
        );
        assert_eq!(
            updated.dispatch_behavior_identity(),
            scratch.dispatch_behavior_identity(),
            "{language:?}"
        );
    }

    /// An ignore-file edit changes which manifests `all_files()` shows, but
    /// `changed_files` holds only the ignore file.
    fn ignore_edit_probe(language: Language, initially_ignored: bool) {
        let (name, source) = jvm_source(language);
        let mut builder = InlineTestProject::with_language(language)
            .file(name, source)
            .file("pom.xml", VERSIONED_POM);
        if initially_ignored {
            builder = builder.file(".gitignore", "pom.xml\n");
        }
        let project = builder.build();
        let base = project.workspace_analyzer(AnalyzerConfig::default());
        let before = external_index_of(&base, language);
        let ignore = project.file(".gitignore");
        ignore
            .write(if initially_ignored {
                "# reveal\n"
            } else {
                "pom.xml\n"
            })
            .unwrap();
        let updated = base.update(&std::collections::BTreeSet::from([ignore]));
        let after = external_index_of(&updated, language);
        assert!(
            !std::sync::Arc::ptr_eq(&before, &after),
            "an ignore edit carried a stale external index for {language:?}"
        );
        assert_equals_from_scratch(&project, &after, language, AnalyzerConfig::default());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12745: a .gitignore edit carried a stale JVM external index"
    )]
    fn gitignore_edit_hiding_or_revealing_a_manifest_does_not_carry_the_index() {
        for language in [Language::Java, Language::Kotlin, Language::Scala] {
            ignore_edit_probe(language, false);
            ignore_edit_probe(language, true);
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12745: a carried JVM external index lost its receipt, so warm reads were unattributed"
    )]
    fn edit_touching_no_dependency_carries_the_index_with_the_from_scratch_receipt() {
        for language in [Language::Java, Language::Kotlin, Language::Scala] {
            let (name, source) = jvm_source(language);
            let project = InlineTestProject::with_language(language)
                .file(name, source)
                .file("pom.xml", VERSIONED_POM)
                .file("build.gradle.kts", "plugins {}")
                .build();
            let base = project.workspace_analyzer(AnalyzerConfig::default());
            let (before, _) =
                capture_query_reads(base.analyzer(), || external_index_of(&base, language));
            let app = project.file(name);
            app.write(format!("{source}\nclass Other")).unwrap();
            // A new source file changes the workspace listing but no dependency.
            let added = project.file("Added.txt");
            added.write("not a manifest").unwrap();
            let updated = base.update(&std::collections::BTreeSet::from([app, added]));
            let (first, first_reads) =
                capture_query_reads(updated.analyzer(), || external_index_of(&updated, language));
            let (second, second_reads) =
                capture_query_reads(updated.analyzer(), || external_index_of(&updated, language));
            let scratch = project.workspace_analyzer(AnalyzerConfig::default());
            let (_, scratch_reads) =
                capture_query_reads(scratch.analyzer(), || external_index_of(&scratch, language));
            assert!(
                std::sync::Arc::ptr_eq(&before, &first),
                "{language:?}: an edit touching no dependency rebuilt the index"
            );
            assert!(std::sync::Arc::ptr_eq(&first, &second));
            for reads in [&first_reads, &second_reads] {
                assert_eq!(reads.unattributed_reads(), 0, "{language:?}: {reads:?}");
                assert_eq!(reads.keys(), scratch_reads.keys(), "{language:?}");
            }
            assert_eq!(scratch_reads.unattributed_reads(), 0);
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12745: a jar rewritten in place under an in-workspace root left a stale JVM external index"
    )]
    fn jar_rewritten_in_place_under_a_workspace_root_does_not_carry_the_index() {
        use super::super::external::{TestClassFile, TestClassMethod, write_test_class_jar};
        for language in [Language::Java, Language::Kotlin, Language::Scala] {
            let (name, source) = jvm_source(language);
            let project = InlineTestProject::with_language(language)
                .file(name, source)
                .file("libs/readme.txt", "jars live here")
                .build();
            let jar = project.file("libs/dep.jar");
            let write_jar = |methods: &[TestClassMethod<'_>]| {
                write_test_class_jar(
                    &jar.abs_path(),
                    &[TestClassFile {
                        internal_name: "org/example/Dep",
                        super_internal_name: "java/lang/Object",
                        methods,
                        private_nested: false,
                    }],
                );
            };
            write_jar(&[]);
            let config = || AnalyzerConfig {
                jvm: brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig {
                    external_dependencies:
                        brokk_bifrost_core::analyzer::config::JvmExternalDependencies {
                            artifact_paths: vec![
                                brokk_bifrost_core::analyzer::config::JvmExternalArtifact {
                                    artifact_path: jar.abs_path(),
                                    ..Default::default()
                                },
                            ],
                            ..Default::default()
                        },
                    ..Default::default()
                },
                ..AnalyzerConfig::default()
            };
            let base = project.workspace_analyzer(config());
            let before = external_index_of(&base, language);
            // Same path, different bytes: the content digest moves.
            write_jar(&[TestClassMethod {
                name: "added",
                descriptor: "()V",
                is_static: false,
            }]);
            let updated = base.update(&std::collections::BTreeSet::from([jar.clone()]));
            let after = external_index_of(&updated, language);
            assert!(
                !std::sync::Arc::ptr_eq(&before, &after),
                "{language:?}: a jar rewritten in place carried a stale index"
            );
            assert_ne!(
                before.dispatch_behavior_identity(),
                after.dispatch_behavior_identity(),
                "{language:?}: the rewrite must change what the index answers"
            );
            assert_equals_from_scratch(&project, &after, language, config());
            // The rebuild published the new jar's inventory, so the next read
            // rebuilds once more (#13384); the carry is tested from that
            // settled index.
            let after = external_index_of(&updated, language);
            // Nothing changed since: the index is carried and still equals it.
            let again = base_update_again(&updated);
            assert!(
                std::sync::Arc::ptr_eq(&after, &external_index_of(&again, language)),
                "{language:?}: an unchanged jar must keep the index"
            );
        }
    }

    const REPO_POM: &str = "<project><dependencies><dependency><groupId>com.example</groupId><artifactId>lib</artifactId><version>1.2.3</version></dependency></dependencies></project>";

    fn repo_jar(repo: &std::path::Path) -> std::path::PathBuf {
        repo.join("com/example/lib/1.2.3/lib-1.2.3.jar")
    }

    fn write_repo_jar(repo: &std::path::Path, extra_method: bool) {
        use super::super::external::{TestClassFile, TestClassMethod, write_test_class_jar};
        let jar = repo_jar(repo);
        std::fs::create_dir_all(jar.parent().unwrap()).unwrap();
        let methods = [TestClassMethod {
            name: "added",
            descriptor: "()V",
            is_static: false,
        }];
        write_test_class_jar(
            &jar,
            &[TestClassFile {
                internal_name: "org/example/Dep",
                super_internal_name: "java/lang/Object",
                methods: if extra_method { &methods } else { &[] },
                private_nested: false,
            }],
        );
    }

    fn repo_config(repo: &std::path::Path) -> AnalyzerConfig {
        AnalyzerConfig {
            jvm: brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig {
                external_dependencies:
                    brokk_bifrost_core::analyzer::config::JvmExternalDependencies {
                        repository_roots: vec![repo.to_path_buf()],
                        ..Default::default()
                    },
                ..Default::default()
            },
            ..AnalyzerConfig::default()
        }
    }

    /// Edit a workspace source file so the next generation exists, leaving every
    /// dependency input alone.
    fn edit_source(
        project: &crate::inline_project::BuiltInlineTestProject,
        base: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        name: &str,
        source: &str,
    ) -> brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer {
        let file = project.file(name);
        file.write(format!("{source}\nclass Edited")).unwrap();
        base.update(&std::collections::BTreeSet::from([file]))
    }

    #[test]
    fn artifact_rewrite_during_decode_is_not_retained_or_carried_after_restore() {
        use super::super::external::{
            JvmExternalDeclarationIndex, TestClassFile, TestClassMethod,
            dependency_discovery_sample, fresh_dependency_discovery_sample, write_test_class_jar,
        };
        for language in [Language::Java, Language::Kotlin, Language::Scala] {
            let (name, source) = jvm_source(language);
            let project = InlineTestProject::with_language(language)
                .file(name, source)
                .build();
            let artifacts = tempfile::tempdir().unwrap();
            let jar = artifacts.path().join("dep.jar");
            let write = |method| {
                write_test_class_jar(
                    &jar,
                    &[TestClassFile {
                        internal_name: "org/example/Dep",
                        super_internal_name: "java/lang/Object",
                        methods: &[TestClassMethod {
                            name: method,
                            descriptor: "()V",
                            is_static: false,
                        }],
                        private_nested: false,
                    }],
                )
            };
            write("first");
            let original = std::fs::read(&jar).unwrap();
            let config = AnalyzerConfig {
                jvm: brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig {
                    external_dependencies:
                        brokk_bifrost_core::analyzer::config::JvmExternalDependencies {
                            artifact_paths: vec![
                                brokk_bifrost_core::analyzer::config::JvmExternalArtifact {
                                    artifact_path: jar.clone(),
                                    ..Default::default()
                                },
                            ],
                            ..Default::default()
                        },
                    ..Default::default()
                },
                ..AnalyzerConfig::default()
            };
            let base = project.workspace_analyzer(config.clone());
            // Let supported devices admit the first sample, so verification
            // also runs with that memo entry alive during the decode.
            std::thread::sleep(std::time::Duration::from_millis(1100));
            let builds = std::cell::Cell::new(0);
            let slot = JvmExternalIndexSlot::new(64 << 20);
            let authority = (
                language,
                match language {
                    Language::Java => WorkspaceFactFamily::JavaExternalDeclarations,
                    Language::Kotlin => WorkspaceFactFamily::KotlinExternalDeclarations,
                    Language::Scala => WorkspaceFactFamily::ScalaExternalIndex,
                    _ => unreachable!(),
                },
            );
            // Model a coarse-tick/Windows metadata collision without relying on
            // the host filesystem's precision: only the transient stat sample
            // is held equal. Both outcome/content samples are production reads.
            let same_stat = |mut sample: (
                brokk_bifrost_analysis::analyzer::semantic::StableDigest,
                bool,
                [u8; 32],
            )| {
                sample.2 = [0; 32];
                sample
            };
            let (wrong, reads) = capture_query_reads(base.analyzer(), || {
                slot.get_or_build(
                    base.analyzer(),
                    authority,
                    || {
                        same_stat(dependency_discovery_sample(
                            base.analyzer(),
                            &config.jvm,
                            base.analyzer().project(),
                        ))
                    },
                    || {
                        same_stat(fresh_dependency_discovery_sample(
                            base.analyzer(),
                            &config.jvm,
                            base.analyzer().project(),
                        ))
                    },
                    |_| {},
                    || {
                        builds.set(builds.get() + 1);
                        write("other");
                        assert_eq!(
                            std::fs::metadata(&jar).unwrap().len(),
                            original.len() as u64
                        );
                        JvmExternalDeclarationIndex::build_for_project(
                            &config.jvm,
                            base.analyzer().project(),
                        )
                    },
                )
            });
            assert!(reads.unattributed_reads() > 0, "{language:?}: {reads:?}");
            assert!(!slot.is_built(), "{language:?}: raced fill retained");
            std::fs::write(&jar, &original).unwrap();
            let updated = edit_source(&project, &base, name, source);
            let successor = slot.updated(64 << 20);
            assert!(
                successor.carry.pending().is_none(),
                "{language:?}: raced fill carried"
            );
            let restored = successor.get_or_build(
                updated.analyzer(),
                authority,
                || {
                    same_stat(dependency_discovery_sample(
                        updated.analyzer(),
                        &config.jvm,
                        base.analyzer().project(),
                    ))
                },
                || {
                    same_stat(fresh_dependency_discovery_sample(
                        updated.analyzer(),
                        &config.jvm,
                        base.analyzer().project(),
                    ))
                },
                |_| {},
                || {
                    builds.set(builds.get() + 1);
                    JvmExternalDeclarationIndex::build_for_project(
                        &config.jvm,
                        base.analyzer().project(),
                    )
                },
            );
            assert_eq!(
                builds.get(),
                2,
                "{language:?}: restored inputs must rebuild"
            );
            assert!(
                successor.is_built(),
                "{language:?}: stable fill not retained"
            );
            assert!(!std::sync::Arc::ptr_eq(&wrong, &restored));
            assert_ne!(
                wrong.dispatch_behavior_identity(),
                restored.dispatch_behavior_identity()
            );
            let cold = JvmExternalDeclarationIndex::build_for_project(
                &config.jvm,
                base.analyzer().project(),
            );
            assert_eq!(
                restored.dispatch_behavior_identity(),
                cold.dispatch_behavior_identity()
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12745: a jar outside the workspace rewritten in place left a carried JVM index with a bounded receipt"
    )]
    fn jar_outside_the_workspace_rewritten_in_place_does_not_carry_the_index() {
        for language in [Language::Java, Language::Kotlin, Language::Scala] {
            let (name, source) = jvm_source(language);
            let repo = tempfile::tempdir().unwrap();
            write_repo_jar(repo.path(), false);
            let project = InlineTestProject::with_language(language)
                .file(name, source)
                .file("pom.xml", REPO_POM)
                .build();
            let base = project.workspace_analyzer(repo_config(repo.path()));
            let before = external_index_of(&base, language);
            // No workspace file reports this change.
            write_repo_jar(repo.path(), true);
            let updated = edit_source(&project, &base, name, source);
            let after = external_index_of(&updated, language);
            assert!(
                !std::sync::Arc::ptr_eq(&before, &after),
                "{language:?}: a jar rewritten outside the workspace was carried"
            );
            assert_ne!(
                before.dispatch_behavior_identity(),
                after.dispatch_behavior_identity(),
                "{language:?}: the rewrite must change what the index answers"
            );
            assert_equals_from_scratch(&project, &after, language, repo_config(repo.path()));
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12745: a jar in an ignored workspace directory rewritten in place left a carried JVM index"
    )]
    fn jar_under_an_ignored_workspace_directory_rewritten_in_place_does_not_carry_the_index() {
        use super::super::external::{TestClassFile, TestClassMethod, write_test_class_jar};
        for language in [Language::Java, Language::Kotlin, Language::Scala] {
            let (name, source) = jvm_source(language);
            let project = InlineTestProject::with_language(language)
                .file(name, source)
                .file(".gitignore", "*.jar\n")
                .file("buildSrc/readme.txt", "ignored jars live here")
                .build();
            let jar = project.file("buildSrc/dep.jar");
            let write_jar = |methods: &[TestClassMethod<'_>]| {
                write_test_class_jar(
                    &jar.abs_path(),
                    &[TestClassFile {
                        internal_name: "org/example/Dep",
                        super_internal_name: "java/lang/Object",
                        methods,
                        private_nested: false,
                    }],
                );
            };
            write_jar(&[]);
            let config = || AnalyzerConfig {
                jvm: brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig {
                    external_dependencies:
                        brokk_bifrost_core::analyzer::config::JvmExternalDependencies {
                            artifact_paths: vec![
                                brokk_bifrost_core::analyzer::config::JvmExternalArtifact {
                                    artifact_path: jar.abs_path(),
                                    ..Default::default()
                                },
                            ],
                            ..Default::default()
                        },
                    ..Default::default()
                },
                ..AnalyzerConfig::default()
            };
            let base = project.workspace_analyzer(config());
            let before = external_index_of(&base, language);
            write_jar(&[TestClassMethod {
                name: "added",
                descriptor: "()V",
                is_static: false,
            }]);
            let updated = edit_source(&project, &base, name, source);
            let after = external_index_of(&updated, language);
            assert!(
                !std::sync::Arc::ptr_eq(&before, &after),
                "{language:?}: an ignored jar rewritten in place was carried"
            );
            assert_ne!(
                before.dispatch_behavior_identity(),
                after.dispatch_behavior_identity()
            );
            assert_equals_from_scratch(&project, &after, language, config());
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12745: a jar added under a scanned repository root left a carried JVM index"
    )]
    fn jar_added_under_a_scanned_root_does_not_carry_the_index() {
        for language in [Language::Java, Language::Kotlin, Language::Scala] {
            let (name, source) = jvm_source(language);
            let repo = tempfile::tempdir().unwrap();
            let project = InlineTestProject::with_language(language)
                .file(name, source)
                .file("pom.xml", REPO_POM)
                .build();
            let base = project.workspace_analyzer(repo_config(repo.path()));
            let before = external_index_of(&base, language);
            write_repo_jar(repo.path(), false);
            let updated = edit_source(&project, &base, name, source);
            let after = external_index_of(&updated, language);
            assert!(
                !std::sync::Arc::ptr_eq(&before, &after),
                "{language:?}: a jar added under a scanned root was carried"
            );
            assert_ne!(before.gap_identity(), after.gap_identity());
            assert_equals_from_scratch(&project, &after, language, repo_config(repo.path()));
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12745: every generation rehashed all dependency artifacts"
    )]
    fn edit_outside_all_inputs_still_carries_with_a_bounded_receipt() {
        for language in [Language::Java, Language::Kotlin, Language::Scala] {
            let (name, source) = jvm_source(language);
            let repo = tempfile::tempdir().unwrap();
            write_repo_jar(repo.path(), false);
            let project = InlineTestProject::with_language(language)
                .file(name, source)
                .file("pom.xml", REPO_POM)
                .build();
            // Leave the conservative one-second racy interval before the
            // initial read, so supported devices can admit the digest.
            std::thread::sleep(std::time::Duration::from_millis(1100));
            let base = project.workspace_analyzer(repo_config(repo.path()));
            let _ = external_index_of(&base, language);
            // The first build publishes its inventory, which moves the store's
            // inventory generation past the one the build sampled; the next read
            // rebuilds once (#13384). Settle that before testing the carry.
            let (before, _) =
                capture_query_reads(base.analyzer(), || external_index_of(&base, language));
            let memo = &base.analyzer().snapshot_caches().unwrap().artifact_digests;
            let original = artifact_inputs_answer(base.analyzer());
            assert!(
                original.is_some(),
                "{language:?}: artifact fact unavailable"
            );
            let before_replay = memo.bytes_hashed();
            assert_eq!(artifact_inputs_answer(base.analyzer()), original);
            let warm_bytes = memo.bytes_hashed() - before_replay;
            let updated = edit_source(&project, &base, name, source);
            let updated_memo = &updated
                .analyzer()
                .snapshot_caches()
                .unwrap()
                .artifact_digests;
            let before_update_replay = updated_memo.bytes_hashed();
            assert_eq!(artifact_inputs_answer(updated.analyzer()), original);
            assert_eq!(
                updated_memo.bytes_hashed() - before_update_replay,
                warm_bytes,
                "{language:?}: a source edit must preserve warm artifact hashing cost"
            );
            let (after, reads) =
                capture_query_reads(updated.analyzer(), || external_index_of(&updated, language));
            let scratch = project.workspace_analyzer(repo_config(repo.path()));
            let (_, scratch_reads) =
                capture_query_reads(scratch.analyzer(), || external_index_of(&scratch, language));
            assert!(
                std::sync::Arc::ptr_eq(&before, &after),
                "{language:?}: an edit outside all inputs rebuilt the index"
            );
            assert_eq!(reads.unattributed_reads(), 0, "{language:?}: {reads:?}");
            assert_eq!(reads.keys(), scratch_reads.keys(), "{language:?}");
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12745: a persisted result survived an outside jar replaced by one with other declarations and the same diagnostics"
    )]
    fn persisted_receipt_misses_when_an_outside_jar_changes_declarations_not_diagnostics() {
        for language in [Language::Java, Language::Kotlin, Language::Scala] {
            let (name, source) = jvm_source(language);
            let repo = tempfile::tempdir().unwrap();
            write_repo_jar(repo.path(), false);
            let project = InlineTestProject::with_language(language)
                .file(name, source)
                .file("pom.xml", REPO_POM)
                .build();
            let base = project.workspace_analyzer(repo_config(repo.path()));
            let (before, reads) =
                capture_query_reads(base.analyzer(), || external_index_of(&base, language));
            assert_eq!(reads.unattributed_reads(), 0, "{language:?}: {reads:?}");
            let verify = |head: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer| {
                brokk_bifrost_analysis::analyzer::read_verification::verify_read_set(
                    head,
                    &ChangedFacts::between(&base, head),
                    &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
                    &reads.keys(),
                    LookupReplayLimits::default(),
                    &NoSummaryAnswers,
                    &mut LookupMemo::new(),
                )
            };
            assert_eq!(verify(&base), ReadVerdict::Unchanged, "{language:?}");
            // Other declarations, no new gap: the gap identity cannot see it.
            write_repo_jar(repo.path(), true);
            let head = project.workspace_analyzer(repo_config(repo.path()));
            let after = external_index_of(&head, language);
            assert_eq!(
                before.gap_identity(),
                after.gap_identity(),
                "{language:?}: the diagnostics must not change"
            );
            assert_ne!(
                before.dispatch_behavior_identity(),
                after.dispatch_behavior_identity(),
                "{language:?}: the declarations must change"
            );
            assert_ne!(
                verify(&head),
                ReadVerdict::Unchanged,
                "{language:?}: a persisted result was reused over a replaced jar"
            );
            let updated = edit_source(&project, &base, name, source);
            assert_equals_from_scratch(
                &project,
                &external_index_of(&updated, language),
                language,
                repo_config(repo.path()),
            );
        }
    }

    /// The index's read receipt over a repository root that lies inside the
    /// workspace, checked against heads built after each filesystem change.
    /// Artifact identity is content (`JvmArtifactInputs`), never stat (#13404).
    struct InWorkspaceRepo {
        project: crate::inline_project::BuiltInlineTestProject,
        repo: std::path::PathBuf,
        base: brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        keys: Vec<brokk_bifrost_analysis::analyzer::ReadKey>,
        before: std::sync::Arc<super::super::external::JvmExternalDeclarationIndex>,
    }

    impl InWorkspaceRepo {
        fn new(jar_present: bool) -> Self {
            let project = InlineTestProject::with_language(Language::Java)
                .file("App.java", "class App {}")
                .file("pom.xml", REPO_POM)
                .file("repo/readme.txt", "repository")
                .build();
            let repo = project.root().join("repo");
            if jar_present {
                write_repo_jar(&repo, false);
                // The conservative racy interval: the digest memo admits a
                // file only once it is old enough.
                std::thread::sleep(std::time::Duration::from_millis(1100));
            }
            let base = project.workspace_analyzer(repo_config(&repo));
            let (before, reads) =
                capture_query_reads(base.analyzer(), || external_index_of(&base, Language::Java));
            assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
            Self {
                keys: reads.keys(),
                project,
                repo,
                base,
                before,
            }
        }

        fn verify(
            &self,
            head: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        ) -> ReadVerdict {
            brokk_bifrost_analysis::analyzer::read_verification::verify_read_set(
                head,
                &ChangedFacts::between(&self.base, head),
                &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
                &self.keys,
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::new(),
            )
        }

        fn scratch(&self) -> brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer {
            self.project.workspace_analyzer(repo_config(&self.repo))
        }

        /// The receipt must be `Changed`, and the incremental index must equal
        /// a from-scratch one.
        fn assert_changed_and_converged(&self, what: &str) {
            let scratch = self.scratch();
            assert_ne!(self.verify(&scratch), ReadVerdict::Unchanged, "{what}");
            let updated = edit_source(&self.project, &self.base, "App.java", "class App {}");
            let after = external_index_of(&updated, Language::Java);
            assert!(
                !std::sync::Arc::ptr_eq(&self.before, &after),
                "{what}: carried a stale index"
            );
            assert_equals_from_scratch(
                &self.project,
                &after,
                Language::Java,
                repo_config(&self.repo),
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13404: stat churn of unlisted or byte-identical files under an in-workspace repository root invalidated persisted receipts"
    )]
    fn in_workspace_repository_churn_without_content_change_keeps_the_receipt() {
        let fixture = InWorkspaceRepo::new(true);
        assert_eq!(fixture.verify(&fixture.base), ReadVerdict::Unchanged);
        // A byte-identical rewrite: new inode and mtime, same sha256.
        let jar = repo_jar(&fixture.repo);
        let bytes = std::fs::read(&jar).unwrap();
        std::fs::remove_file(&jar).unwrap();
        std::fs::write(&jar, &bytes).unwrap();
        // Unlisted files: one added, one touched.
        std::fs::write(fixture.repo.join("unlisted.bin"), b"new").unwrap();
        std::fs::write(fixture.repo.join("readme.txt"), b"touched repository").unwrap();
        // The head publishes its provider inventory before verification, as
        // a real head's build would.
        let head = fixture.scratch();
        let _ = external_index_of(&head, Language::Java);
        assert_eq!(
            fixture.verify(&head),
            ReadVerdict::Unchanged,
            "stat churn without a content change must keep the receipt"
        );
    }

    #[test]
    fn in_workspace_listed_jar_content_change_invalidates_the_receipt() {
        let fixture = InWorkspaceRepo::new(true);
        write_repo_jar(&fixture.repo, true);
        fixture.assert_changed_and_converged("changed jar bytes");
    }

    #[test]
    fn in_workspace_listed_jar_removal_invalidates_the_receipt() {
        let fixture = InWorkspaceRepo::new(true);
        std::fs::remove_file(repo_jar(&fixture.repo)).unwrap();
        fixture.assert_changed_and_converged("removed jar");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13404: a missing coordinate whose jar later appears under an in-workspace repository root stayed masked (#10470)"
    )]
    fn missing_coordinate_jar_added_under_an_in_workspace_root_invalidates_the_receipt() {
        let fixture = InWorkspaceRepo::new(false);
        assert_eq!(fixture.verify(&fixture.base), ReadVerdict::Unchanged);
        write_repo_jar(&fixture.repo, false);
        fixture.assert_changed_and_converged("added jar");
    }

    fn base_update_again(
        workspace: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
    ) -> brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer {
        workspace.update(&std::collections::BTreeSet::new())
    }

    #[test]
    fn dependency_shaped_edit_does_not_carry_the_index() {
        for language in [Language::Java, Language::Kotlin, Language::Scala] {
            for (manifest, contents) in [
                ("pom.xml", VERSIONED_POM),
                (
                    "build.gradle.kts",
                    "dependencies { implementation(\"a:b:1\") }",
                ),
                ("sub/pom.xml", VERSIONED_POM),
            ] {
                let (name, source) = jvm_source(language);
                let project = InlineTestProject::with_language(language)
                    .file(name, source)
                    .build();
                let base = project.workspace_analyzer(AnalyzerConfig::default());
                let before = external_index_of(&base, language);
                let created = project.file(manifest);
                created.write(contents).unwrap();
                let updated = base.update(&std::collections::BTreeSet::from([created]));
                let after = external_index_of(&updated, language);
                assert!(
                    !std::sync::Arc::ptr_eq(&before, &after),
                    "{language:?}: creating {manifest} carried the index"
                );
                assert_equals_from_scratch(&project, &after, language, AnalyzerConfig::default());
            }
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#7496: warm JVM authority hits omitted their inputs from policy read sets"
    )]
    fn warm_external_indexes_record_build_files_and_absent_candidates() {
        for language in [Language::Java, Language::Kotlin, Language::Scala] {
            let (name, source) = match language {
                Language::Java => ("App.java", "class App {}"),
                Language::Kotlin => ("App.kt", "class App"),
                Language::Scala => ("App.scala", "class App"),
                _ => unreachable!(),
            };
            let project = InlineTestProject::with_language(language)
                .file(name, source)
                .file("pom.xml", "<project/>")
                .file("build.gradle.kts", "plugins {}")
                .build();
            let base = project.workspace_analyzer(AnalyzerConfig::default());
            let read = || match language {
                Language::Java => {
                    let java =
                        brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                            crate::analyzer::java::JavaAnalyzer,
                        >(base.analyzer())
                        .unwrap();
                    java.external_declaration_index()
                        .dispatch_behavior_identity()
                }
                Language::Kotlin => {
                    let kotlin =
                        brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                            crate::analyzer::kotlin::KotlinAnalyzer,
                        >(base.analyzer())
                        .unwrap();
                    kotlin
                        .external_declaration_index()
                        .dispatch_behavior_identity()
                }
                Language::Scala => {
                    let scala =
                        brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                            crate::analyzer::scala::ScalaAnalyzer,
                        >(base.analyzer())
                        .unwrap();
                    scala
                        .external_declaration_index()
                        .dispatch_behavior_identity()
                }
                _ => unreachable!(),
            };
            let warmed = read();
            // The receipt belongs to the uncaptured fill. Deliberately edit
            // the mutable project before attaching a capture, and require the
            // old blob rather than certifying the old index with new inputs.
            project
                .file("pom.xml")
                .write("<project><!-- before capture --></project>")
                .unwrap();
            let (identity, reads) = capture_query_reads(base.analyzer(), read);
            let (again_identity, again) = capture_query_reads(base.analyzer(), read);
            assert_eq!(warmed, identity);
            assert_eq!(identity, again_identity);
            let filled_blob =
                git2::Oid::hash_object(git2::ObjectType::Blob, b"<project/>").unwrap();
            assert!(
                reads.keys().iter().any(|key| matches!(key,
                ReadKey::File { rel_path, blob, .. }
                if rel_path.as_ref() == "pom.xml" && *blob == filled_blob)),
                "{reads:?}"
            );
            project.file("pom.xml").write("<project/>").unwrap();
            assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
            assert_eq!(reads.keys(), again.keys());
            for input in ["pom.xml", "build.gradle.kts"] {
                assert!(
                    reads.keys().iter().any(|key| matches!(key,
                    ReadKey::File { rel_path, .. } if rel_path.as_ref() == input)),
                    "{reads:?}"
                );
            }
            assert!(
                reads.keys().iter().any(|key| matches!(key,
                ReadKey::PathAbsent { rel_path, .. } if rel_path.as_ref() == "gradle.lockfile")),
                "{reads:?}"
            );
            let verify = |head: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer| {
                brokk_bifrost_analysis::analyzer::read_verification::verify_read_set(
                    head,
                    &ChangedFacts::between(&base, head),
                    &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
                    &reads.keys(),
                    LookupReplayLimits::default(),
                    &NoSummaryAnswers,
                    &mut LookupMemo::new(),
                )
            };
            assert_eq!(verify(&base), ReadVerdict::Unchanged);
            project
                .file("pom.xml")
                .write("<project><!-- changed --></project>")
                .unwrap();
            let edited = project.workspace_analyzer(AnalyzerConfig::default());
            assert_ne!(verify(&edited), ReadVerdict::Unchanged);
            project.file("pom.xml").write("<project/>").unwrap();
            project
                .file("build.gradle.kts")
                .write("plugins {} // changed")
                .unwrap();
            let gradle_edit = project.workspace_analyzer(AnalyzerConfig::default());
            assert_ne!(verify(&gradle_edit), ReadVerdict::Unchanged);
            project
                .file("build.gradle.kts")
                .write("plugins {}")
                .unwrap();
            project
                .file("gradle.lockfile")
                .write("# lockfile created")
                .unwrap();
            let added = project.workspace_analyzer(AnalyzerConfig::default());
            assert_ne!(verify(&added), ReadVerdict::Unchanged);
        }
    }
}

#[cfg(test)]
pub(crate) fn assert_receipt_loss_refuses_live_index(
    analyzer: &dyn IAnalyzer,
    slot: &JvmExternalIndexSlot,
    read: impl Fn(),
) {
    use brokk_bifrost_analysis::analyzer::{ReadKey, capture_query_reads};
    read();
    let built = std::sync::Arc::clone(
        slot.index
            .read()
            .unwrap()
            .get()
            .expect("must build the real language index"),
    );
    assert_eq!(
        slot.receipt.account(|cache| {
            cache.run_pending_tasks();
            usize::from(cache.get(&()).is_none())
        }),
        1,
        "the tiny receipt budget must actually discard the receipt"
    );
    std::fs::write(
        analyzer.project().root().join("pom.xml"),
        "<project><!-- changed after build --></project>",
    )
    .unwrap();
    for _ in 0..2 {
        let (_, reads) = capture_query_reads(analyzer, &read);
        assert!(
            reads.unattributed_reads() > 0,
            "a live index without its receipt must refuse: {reads:?}"
        );
        assert!(
            !reads.keys().iter().any(|key| matches!(key,
            ReadKey::File { rel_path, .. } if rel_path.as_ref() == "pom.xml")),
            "a lost receipt must never be recreated from current manifests: {reads:?}"
        );
        assert!(
            std::sync::Arc::ptr_eq(&built, slot.index.read().unwrap().get().unwrap().replay()),
            "must keep the original index"
        );
    }
}

#[cfg(test)]
mod failed_input_tests {
    use super::*;
    use crate::analyzer::scala::ScalaAnalyzer;
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::{LookupQuestion, ReadKey, capture_query_reads};

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2445: Scala external inputs omitted the dependency inputs and absent manifests"
    )]
    fn scala_external_index_build_records_dependency_inputs_and_absent_manifests() {
        let project = InlineTestProject::with_language(Language::Scala)
            .file("App.scala", "class App")
            .build();
        let scala = ScalaAnalyzer::new(project.project_arc());
        scala.external_declaration_index();
        let (_, reads) = capture_query_reads(&scala, || {
            scala.external_declaration_index();
        });
        assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
        assert!(
            reads.keys().iter().any(|key| matches!(
                key,
                ReadKey::Lookup {
                    question: LookupQuestion::WorkspaceFact {
                        family: WorkspaceFactFamily::JvmDependencyInputs,
                        ..
                    },
                    ..
                }
            )),
            "{reads:?}"
        );
        for candidate in ["pom.xml", "build.gradle", "gradle.lockfile"] {
            assert!(reads.keys().iter().any(|key| matches!(key,
                ReadKey::PathAbsent { language: Language::Scala, rel_path } if rel_path.as_ref() == candidate)), "{reads:?}");
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2445: failed Scala manifest snapshots were silently dropped from receipts"
    )]
    fn failed_manifest_snapshot_refuses_subsequent_external_index_hits() {
        let project = InlineTestProject::with_language(Language::Scala)
            .file("App.scala", "class App")
            .build();
        std::fs::create_dir(project.root().join("pom.xml")).unwrap();
        let scala = ScalaAnalyzer::new(project.project_arc());
        scala.external_declaration_index();
        for _ in 0..2 {
            let (_, reads) = capture_query_reads(&scala, || {
                scala.external_declaration_index();
            });
            assert!(
                reads.unattributed_reads() > 0,
                "failed snapshots must remain a refusal: {reads:?}"
            );
        }
    }
}
