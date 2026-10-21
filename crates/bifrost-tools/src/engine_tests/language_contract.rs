#[cfg(test)]
mod tests {

    use brokk_bifrost_analysis::analyzer::languages::EdgePassEntry;

    use brokk_bifrost_analysis::analyzer::languages::EdgePassId;

    use brokk_bifrost_analysis::analyzer::languages::EdgeSiteScanCtx;

    use brokk_bifrost_analysis::analyzer::languages::EdgeWeightScanCtx;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::languages::LanguageEdgePass;

    use brokk_bifrost_analysis::analyzer::languages::LanguageEdgeSites;

    use brokk_bifrost_analysis::analyzer::languages::LanguageEdgeWeights;

    use brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend;

    use brokk_bifrost_analysis::analyzer::languages::LanguageSupport;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

    use brokk_bifrost_analysis::analyzer::languages::claim_inferring_languages;

    use brokk_bifrost_analysis::analyzer::languages::edge_passes;

    use brokk_bifrost_analysis::analyzer::languages::graph_authority_digest;

    use brokk_bifrost_analysis::analyzer::languages::graph_authority_digest_of;

    use brokk_bifrost_analysis::analyzer::languages::language_support;
    use brokk_bifrost_core::analyzer::common::INCLUDE_CLAIMING_LANGUAGE;
    use brokk_bifrost_test_macros::hardwon;
    use std::collections::{BTreeMap, BTreeSet};

    const ANALYZABLE: [Language; 12] = [
        Language::Java,
        Language::Go,
        Language::Cpp,
        Language::JavaScript,
        Language::TypeScript,
        Language::Python,
        Language::Rust,
        Language::Php,
        Language::Scala,
        Language::CSharp,
        Language::Ruby,
        Language::Kotlin,
    ];

    fn support_of(language: Language) -> &'static dyn LanguageSupport {
        language_support(language).unwrap_or_else(|| panic!("{language:?} must be registered"))
    }

    /// Every observable capability of every registered language, as one reviewed table.
    ///
    /// Centralized defaults keep an absent capability silent by design -- that is the whole
    /// point of the trait's defaults -- so this snapshot is what makes the silence visible:
    /// a capability appearing or disappearing arrives as a diff here instead of as a change
    /// in behavior nobody looked at. It is also the single source of truth the capability
    /// documentation matrix renders from.
    ///
    /// Absences the table records rather than merely permits, each a real user-visible
    /// behavior: C++ and Python have no per-symbol dead-code strategy because their
    /// candidates are always proven in bulk; Kotlin now uses a bulk proof for classes and
    /// callable declarations while fields and duplicate-FQN functions stay precise; Java and
    /// JS/TS answer no structural
    /// receiver because their receiver analysis runs another route entirely (a resolution
    /// session, and the JS/TS syntax index reached through `facts`).
    ///
    /// There is no type-lookup column: `get_type_by_location` dispatches through the
    /// same bounded receiver contract this table's `recv` column records, with Java and
    /// JS/TS served by the same other routes `recv`/`facts` name, so every registered
    /// language answers it and a separate column would restate those three.
    ///
    /// Deliberately observable-only. Behind `dyn` there is no way to distinguish an
    /// inherited default from an identical override, and a hand-maintained
    /// implemented-versus-default table would recreate the parallel capability list this
    /// refactor exists to delete. Three capabilities are therefore absent here rather than
    /// forgotten, because none answers anything without a built workspace:
    /// `candidate_augmentation` needs an analyzer and a target, and
    /// `signature_metadata_limited`, `signatures_limited`, and
    /// `declaration_ranges_limited` need an analyzer and a `CodeUnit`. Each is pinned by its
    /// own behavior test instead.
    const CAPABILITY_MATRIX: &str = "\
language   | ecosystem            | pass   | graph  | sep | strategy | bulk   | recv | facts | hl  | tflow
Java       | Jvm                  | Java   | legacy | .   | yes      | Java   | -    | -     | yes | -
Go         | Go                   | Go     | legacy | /   | yes      | Go     | yes  | -     | yes | -
Cpp        | Cpp                  | Cpp    | legacy | ::  | -        | Cpp    | yes  | -     | yes | -
JavaScript | JavaScriptTypeScript | JsTs   | legacy | .   | yes      | JsTs   | -    | yes   | yes | yes
TypeScript | JavaScriptTypeScript | JsTs   | legacy | .   | yes      | JsTs   | -    | yes   | yes | yes
Python     | Python               | Python | legacy | .   | -        | Python | yes  | -     | yes | yes
Rust       | Rust                 | Rust   | native | .   | yes      | Rust   | yes  | -     | yes | -
Php        | Php                  | Php    | legacy | .   | yes      | Php    | yes  | -     | yes | yes
Scala      | Jvm                  | Scala  | legacy | .   | yes      | Scala  | yes  | -     | yes | -
CSharp     | CSharp               | CSharp | legacy | .   | yes      | CSharp | yes  | -     | yes | -
Ruby       | Ruby                 | Ruby   | legacy | .   | yes      | Ruby   | yes  | -     | yes | yes
Kotlin     | Jvm                  | Kotlin | legacy | .   | yes      | Kotlin | yes  | -     | yes | -
";

    fn mark(present: bool) -> &'static str {
        if present { "yes" } else { "-" }
    }

    fn capability_matrix() -> String {
        let mut rendered = String::from(
            "language   | ecosystem            | pass   | graph  | sep | strategy | bulk   | recv | facts | hl  | tflow\n",
        );
        for language in ANALYZABLE {
            let support = support_of(language);
            let dead_code = support.dead_code();
            let backend = support.reference_plugin().graph;
            let backend_name = match backend {
                LanguageGraphBackend::Legacy(_) => "legacy",
                LanguageGraphBackend::Native(_) => "native",
            };
            let bulk = match backend {
                LanguageGraphBackend::Native(provider) => Some(provider.id()),
                LanguageGraphBackend::Legacy(_) => dead_code.bulk.map(|bulk| bulk.id()),
            };
            rendered.push_str(&format!(
                "{:<10} | {:<20} | {:<6} | {:<6} | {:<3} | {:<8} | {:<6} | {:<4} | {:<5} | {:<3} | {}\n",
                format!("{language:?}"),
                format!("{:?}", support.ecosystem()),
                format!("{:?}", backend.id()),
                backend_name,
                support.knowledge().package_separator(),
                mark(dead_code.strategy.is_some()),
                bulk.map_or_else(|| "-".to_string(), |bulk| format!("{bulk:?}")),
                mark(support.structural_receiver().is_some()),
                mark(support.receiver_facts().is_some()),
                mark(support.knowledge().highlight_query().is_some()),
                mark(support.type_flow_adapter().is_some()),
            ));
        }
        rendered
    }

    #[test]
    fn the_capability_matrix_matches_its_snapshot() {
        assert_eq!(capability_matrix(), CAPABILITY_MATRIX);
    }

    /// Flipping one language's graph authority must move the digest that every
    /// cross-engine identity folds.
    ///
    /// The workspace usage-graph cache key and the analysis epoch a recorded
    /// read set carries both fold `graph_authority_digest`. Before it existed,
    /// the only thing separating a pre-flip identity from a post-flip one was a
    /// hand-bumped representation constant, so a derived artifact built by the
    /// legacy Rust resolver and one built by the native engine shared an id
    /// whenever the bytes were equal.
    #[test]
    #[hardwon("#1630: graph-authority changes must invalidate derived artifact identities")]
    fn the_graph_authority_digest_separates_a_flipped_language_from_production() {
        struct StandInLegacyPass(EdgePassId);
        impl LanguageEdgePass for StandInLegacyPass {
            fn id(&self) -> EdgePassId {
                self.0
            }

            fn edge_sites(&self, _ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites> {
                unimplemented!("the authority digest reads registration, never a scan")
            }

            fn edge_weights(&self, _ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
                unimplemented!("the authority digest reads registration, never a scan")
            }
        }
        static RUST_LEGACY_STAND_IN: StandInLegacyPass = StandInLegacyPass(EdgePassId::Rust);

        let production = edge_passes();
        assert!(
            matches!(
                production
                    .iter()
                    .find(|entry| entry.id == EdgePassId::Rust)
                    .expect("Rust owns an edge pass")
                    .backend,
                LanguageGraphBackend::Native(_)
            ),
            "Rust is registered on the native graph authority"
        );
        assert_eq!(
            graph_authority_digest_of(&production),
            graph_authority_digest(),
            "the production digest is the digest of the production registry"
        );

        let flipped: Vec<EdgePassEntry> = production
            .into_iter()
            .map(|entry| EdgePassEntry {
                backend: if entry.id == EdgePassId::Rust {
                    LanguageGraphBackend::Legacy(&RUST_LEGACY_STAND_IN)
                } else {
                    entry.backend
                },
                ..entry
            })
            .collect();
        assert_ne!(
            graph_authority_digest_of(&flipped),
            graph_authority_digest(),
            "one language on the other authority is a different engine"
        );
    }

    fn edge_pass_id_of(language: Language) -> EdgePassId {
        support_of(language).reference_plugin().graph.id()
    }

    /// Pass cardinality is the whole reason [`EdgePassId`] exists: it is neither one per
    /// language nor one per ecosystem, and getting it wrong is silent. Collapsing the JVM
    /// trio would drop two of the three resolvers; splitting JS/TS would run one scan
    /// twice and double every JS/TS edge weight.
    #[test]
    fn passes_are_shared_by_dialect_and_split_by_resolver() {
        assert_eq!(
            edge_pass_id_of(Language::JavaScript),
            edge_pass_id_of(Language::TypeScript),
            "JavaScript and TypeScript are served by one pass"
        );
        let jvm = [Language::Java, Language::Scala, Language::Kotlin].map(edge_pass_id_of);
        assert_eq!(
            BTreeSet::from(jvm).len(),
            3,
            "Java, Scala and Kotlin run three distinct passes: {jvm:?}"
        );

        let mut owners: BTreeMap<EdgePassId, Vec<Language>> = BTreeMap::new();
        for language in ANALYZABLE {
            owners
                .entry(edge_pass_id_of(language))
                .or_default()
                .push(language);
        }
        for (id, languages) in &owners {
            assert!(
                languages.len() == 1
                    || *languages == vec![Language::JavaScript, Language::TypeScript],
                "{id:?} is shared by unrelated languages {languages:?}"
            );
        }
        assert_eq!(
            owners.keys().copied().collect::<Vec<_>>(),
            EdgePassId::ALL
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>(),
            "every declared pass id is owned, and no language reports an undeclared one"
        );
    }

    /// `LanguageEdgePass` has no `ecosystem()` on purpose -- `LanguageSupport` is the
    /// single owner -- which only holds if the languages sharing a pass agree. This is the
    /// assertion `edge_passes` makes at runtime, checked here against the whole registry.
    #[test]
    fn languages_sharing_a_pass_agree_on_their_ecosystem() {
        let mut ecosystem_of: BTreeMap<EdgePassId, (Language, UsageEcosystem)> = BTreeMap::new();
        for language in ANALYZABLE {
            let support = support_of(language);
            let id = edge_pass_id_of(language);
            match ecosystem_of.get(&id) {
                None => {
                    ecosystem_of.insert(id, (language, support.ecosystem()));
                }
                Some((owner, ecosystem)) => assert_eq!(
                    *ecosystem,
                    support.ecosystem(),
                    "{language:?} and {owner:?} share {id:?} but disagree on their ecosystem"
                ),
            }
        }
        assert_eq!(
            edge_passes().len(),
            ecosystem_of.len(),
            "the collector deduplicates to exactly the distinct pass ids"
        );
    }

    /// A support must find its own analyzer and no other's: a mis-wired downcast would
    /// silently answer forward queries from the wrong language's declarations.
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    /// `brokk-bifrost-core` cannot reach this CLAIMS SEAM registry, but it has
    /// to name declarations found in the files inference claims -- an
    /// unclaimed-extension file renders its qualified name in the claiming
    /// language rather than `Language::None` (#1878). Its copy of the fact must
    /// track this one.
    #[test]
    #[hardwon("#1878: include-claimed declarations must use the same claiming-language registry")]
    fn core_claiming_language_matches_the_claims_seam() {
        assert_eq!(
            [INCLUDE_CLAIMING_LANGUAGE].as_slice(),
            claim_inferring_languages(),
            "core's INCLUDE_CLAIMING_LANGUAGE must name exactly the claim-inferring registry"
        );
    }
}
