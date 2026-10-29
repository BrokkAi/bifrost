//! Language precedence data and the file-local root-import lowering form.
//!
//! Rules are static. Each lowering works on one file and retains no inventory.

use super::local_identity::ResolutionIdentityCatalogBuilder;
use super::model::{BindingOrigin, PrecedenceStep, SemanticId};
use crate::analyzer::structural::PrecedenceTier;
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionNamespace, ResolutionRootImportFact, ResolutionRootImportKind,
};

pub(crate) trait PrecedenceRules: Sync {
    /// Lower is stronger; path comparison remains shared.
    fn origin_rank(&self, _origin: BindingOrigin) -> Option<u32> {
        None
    }

    fn root_import_tier(&self, _kind: ResolutionRootImportKind) -> PrecedenceTier {
        PrecedenceTier::WildcardImport
    }

    fn root_import_steps(
        &self,
        identities: &mut ResolutionIdentityCatalogBuilder,
        _import: &ResolutionRootImportFact,
        kind: ResolutionRootImportKind,
        choice: SemanticId,
        namespace: ResolutionNamespace,
    ) -> Vec<PrecedenceStep> {
        let mut precedence = vec![identities.register_precedence_namespace(
            PrecedenceStep {
                tier: self.root_import_tier(kind),
                ordinal: 0,
                semantic: choice,
            },
            namespace,
        )];
        let origin = if kind == ResolutionRootImportKind::Named {
            BindingOrigin::ExplicitImport
        } else {
            BindingOrigin::WildcardImport
        };
        if let Some(ordinal) = self.origin_rank(origin) {
            precedence.push(identities.register_precedence_namespace(
                PrecedenceStep {
                    tier: PrecedenceTier::CandidateOriginRank,
                    ordinal,
                    semantic: choice,
                },
                namespace,
            ));
        }
        precedence
    }
}

struct JvmPrecedenceRules {
    origin_rank: fn(BindingOrigin) -> Option<u32>,
}
impl PrecedenceRules for JvmPrecedenceRules {
    fn origin_rank(&self, origin: BindingOrigin) -> Option<u32> {
        (self.origin_rank)(origin)
    }
    fn root_import_tier(&self, kind: ResolutionRootImportKind) -> PrecedenceTier {
        match kind {
            ResolutionRootImportKind::Named => PrecedenceTier::ExplicitImport,
            ResolutionRootImportKind::Glob => PrecedenceTier::WildcardImport,
        }
    }
}
struct DefaultPrecedenceRules;
impl PrecedenceRules for DefaultPrecedenceRules {}
struct GoPrecedenceRules;
impl PrecedenceRules for GoPrecedenceRules {
    fn root_import_steps(
        &self,
        identities: &mut ResolutionIdentityCatalogBuilder,
        import: &ResolutionRootImportFact,
        _kind: ResolutionRootImportKind,
        _choice: SemanticId,
        _namespace: ResolutionNamespace,
    ) -> Vec<PrecedenceStep> {
        super::fact_lowering::go_spelling_precedence(identities, import.root_scope, None, 0)
    }
}
struct RustPrecedenceRules;
impl PrecedenceRules for RustPrecedenceRules {
    fn root_import_steps(
        &self,
        identities: &mut ResolutionIdentityCatalogBuilder,
        import: &ResolutionRootImportFact,
        kind: ResolutionRootImportKind,
        choice: SemanticId,
        namespace: ResolutionNamespace,
    ) -> Vec<PrecedenceStep> {
        super::fact_lowering::rust_root_import_precedence(
            identities, import, kind, choice, namespace,
        )
    }
}

pub(crate) fn precedence_rules(language: Language) -> &'static dyn PrecedenceRules {
    static JAVA: JvmPrecedenceRules = JvmPrecedenceRules {
        origin_rank: java_binding_origin_rank,
    };
    static KOTLIN: JvmPrecedenceRules = JvmPrecedenceRules {
        origin_rank: kotlin_binding_origin_rank,
    };
    static SCALA: JvmPrecedenceRules = JvmPrecedenceRules {
        origin_rank: scala_binding_origin_rank,
    };
    static RUST: RustPrecedenceRules = RustPrecedenceRules;
    static GO: GoPrecedenceRules = GoPrecedenceRules;
    static PYTHON: DefaultPrecedenceRules = DefaultPrecedenceRules;
    static CSHARP: DefaultPrecedenceRules = DefaultPrecedenceRules;
    static DEFAULT: DefaultPrecedenceRules = DefaultPrecedenceRules;
    match language {
        Language::Java => &JAVA,
        Language::Kotlin => &KOTLIN,
        Language::Scala => &SCALA,
        Language::Rust => &RUST,
        Language::Go => &GO,
        Language::Python => &PYTHON,
        Language::CSharp => &CSHARP,
        _ => &DEFAULT,
    }
}

fn java_binding_origin_rank(origin: BindingOrigin) -> Option<u32> {
    use BindingOrigin as Origin;
    match origin {
        Origin::DefaultImport => Some(4),
        Origin::RootPackage => None,
        Origin::LocalOrInherited => Some(0),
        Origin::SingleTypeImport | Origin::ExplicitImport => Some(1),
        Origin::SamePackage
        | Origin::SameCompilationUnitPackage
        | Origin::OtherCompilationUnitPackage => Some(2),
        Origin::OnDemandImport | Origin::WildcardImport | Origin::StarImport => Some(3),
    }
}

fn kotlin_binding_origin_rank(origin: BindingOrigin) -> Option<u32> {
    use BindingOrigin as Origin;
    match origin {
        Origin::DefaultImport | Origin::RootPackage => Some(4),
        Origin::LocalOrInherited => Some(0),
        Origin::ExplicitImport => Some(1),
        Origin::SamePackage | Origin::SameCompilationUnitPackage => Some(2),
        Origin::WildcardImport | Origin::StarImport | Origin::OnDemandImport => Some(3),
        Origin::OtherCompilationUnitPackage | Origin::SingleTypeImport => None,
    }
}

fn scala_binding_origin_rank(origin: BindingOrigin) -> Option<u32> {
    use BindingOrigin as Origin;
    match origin {
        Origin::LocalOrInherited | Origin::SameCompilationUnitPackage => Some(0),
        Origin::ExplicitImport => Some(1),
        Origin::WildcardImport | Origin::StarImport => Some(2),
        Origin::OtherCompilationUnitPackage => Some(3),
        Origin::RootPackage | Origin::DefaultImport => Some(4),
        Origin::SingleTypeImport | Origin::OnDemandImport | Origin::SamePackage => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::resolution_facts::{
        ResolutionImportRouteKind, ResolutionImportSelectorKind,
    };
    // #7314: the pre-extraction JVM values are the contract for the rules seam.
    #[test]
    fn jvm_rank_table_matches_base_contract() {
        use super::super::model::binding_origin_rank;
        use crate::analyzer::store::resolution_operation::jvm_context::{
            jvm_assembled_import_origin, jvm_bridge_import_origin, jvm_lexical_import_head_origin,
            jvm_package_precedence_origin,
        };
        use crate::analyzer::store::resolution_operation::jvm_demand::jvm_root_import_origin;
        use crate::analyzer::store::resolution_operation::nominal_rules::PackageRelation;
        use BindingOrigin::*;
        use ResolutionImportRouteKind as Route;
        use ResolutionImportSelectorKind as Selector;
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportKind;
        use std::fmt::Write as _;

        let mut rendered = String::new();
        for language in [Language::Java, Language::Kotlin, Language::Scala] {
            for origin in [
                LocalOrInherited,
                ExplicitImport,
                WildcardImport,
                SameCompilationUnitPackage,
                OtherCompilationUnitPackage,
                SingleTypeImport,
                OnDemandImport,
                SamePackage,
                StarImport,
                RootPackage,
                DefaultImport,
            ] {
                writeln!(
                    rendered,
                    "{language:?} origin {origin:?} = {:?}",
                    binding_origin_rank(language, origin)
                )
                .unwrap();
            }
            for (kind, import_kind) in [
                ("Named", ResolutionRootImportKind::Named),
                ("Glob", ResolutionRootImportKind::Glob),
            ] {
                writeln!(
                    rendered,
                    "{language:?} root {kind} = {:?}",
                    jvm_root_import_origin(language, import_kind)
                )
                .unwrap();
            }
            for (relation, package_relation) in [
                ("SamePackage", PackageRelation::SamePackage),
                ("OtherPackage", PackageRelation::OtherPackage),
            ] {
                let (tier, origin) = jvm_package_precedence_origin(language, package_relation);
                writeln!(
                    rendered,
                    "{language:?} package {relation} = {tier:?} {origin:?}"
                )
                .unwrap();
            }
            for (context, prefix_length, caller_version, target_version) in [
                ("full-route", 2, Some(1), Some(1)),
                ("package-prefix-same-unit", 1, Some(1), Some(1)),
                ("package-prefix-other-unit", 1, Some(1), Some(2)),
                ("package-prefix-unknown-unit", 1, None, None),
            ] {
                for selector in [
                    Some(Selector::Named),
                    Some(Selector::Star),
                    Some(Selector::ReceiverMember),
                    None,
                ] {
                    let origin = jvm_assembled_import_origin(
                        language,
                        prefix_length,
                        2,
                        caller_version,
                        target_version,
                        selector,
                    );
                    writeln!(
                        rendered,
                        "{language:?} assembly {context} selector={selector:?} = {origin:?}"
                    )
                    .unwrap();
                }
            }
            for route in [
                Some(Route::SingleType),
                Some(Route::TypeOnDemand),
                Some(Route::SingleStatic),
                Some(Route::StaticOnDemand),
                Some(Route::Named),
                Some(Route::Star),
                None,
            ] {
                for selector in [
                    Some(Selector::Named),
                    Some(Selector::Star),
                    Some(Selector::ReceiverMember),
                    None,
                ] {
                    let origin = jvm_bridge_import_origin(language, route, selector);
                    writeln!(
                        rendered,
                        "{language:?} bridge route={route:?} selector={selector:?} = {origin:?}"
                    )
                    .unwrap();
                }
            }
            let lexical_origin = jvm_lexical_import_head_origin(language);
            writeln!(
                rendered,
                "{language:?} lexical-import-head = {lexical_origin:?}"
            )
            .unwrap();
        }
        let expected = "Java origin LocalOrInherited = Some(0)
Java origin ExplicitImport = Some(1)
Java origin WildcardImport = Some(3)
Java origin SameCompilationUnitPackage = Some(2)
Java origin OtherCompilationUnitPackage = Some(2)
Java origin SingleTypeImport = Some(1)
Java origin OnDemandImport = Some(3)
Java origin SamePackage = Some(2)
Java origin StarImport = Some(3)
Java origin RootPackage = None
Java origin DefaultImport = Some(4)
Java root Named = SingleTypeImport
Java root Glob = OnDemandImport
Java package SamePackage = None SamePackage
Java package OtherPackage = None OtherCompilationUnitPackage
Java assembly full-route selector=Some(Named) = SingleTypeImport
Java assembly full-route selector=Some(Star) = WildcardImport
Java assembly full-route selector=Some(ReceiverMember) = OtherCompilationUnitPackage
Java assembly full-route selector=None = OtherCompilationUnitPackage
Java assembly package-prefix-same-unit selector=Some(Named) = SingleTypeImport
Java assembly package-prefix-same-unit selector=Some(Star) = WildcardImport
Java assembly package-prefix-same-unit selector=Some(ReceiverMember) = OtherCompilationUnitPackage
Java assembly package-prefix-same-unit selector=None = OtherCompilationUnitPackage
Java assembly package-prefix-other-unit selector=Some(Named) = SingleTypeImport
Java assembly package-prefix-other-unit selector=Some(Star) = WildcardImport
Java assembly package-prefix-other-unit selector=Some(ReceiverMember) = OtherCompilationUnitPackage
Java assembly package-prefix-other-unit selector=None = OtherCompilationUnitPackage
Java assembly package-prefix-unknown-unit selector=Some(Named) = SingleTypeImport
Java assembly package-prefix-unknown-unit selector=Some(Star) = WildcardImport
Java assembly package-prefix-unknown-unit selector=Some(ReceiverMember) = OtherCompilationUnitPackage
Java assembly package-prefix-unknown-unit selector=None = OtherCompilationUnitPackage
Java bridge route=Some(SingleType) selector=Some(Named) = Some(SingleTypeImport)
Java bridge route=Some(SingleType) selector=Some(Star) = Some(SingleTypeImport)
Java bridge route=Some(SingleType) selector=Some(ReceiverMember) = Some(SingleTypeImport)
Java bridge route=Some(SingleType) selector=None = Some(SingleTypeImport)
Java bridge route=Some(TypeOnDemand) selector=Some(Named) = Some(OnDemandImport)
Java bridge route=Some(TypeOnDemand) selector=Some(Star) = Some(OnDemandImport)
Java bridge route=Some(TypeOnDemand) selector=Some(ReceiverMember) = Some(OnDemandImport)
Java bridge route=Some(TypeOnDemand) selector=None = Some(OnDemandImport)
Java bridge route=Some(SingleStatic) selector=Some(Named) = Some(SingleTypeImport)
Java bridge route=Some(SingleStatic) selector=Some(Star) = Some(SingleTypeImport)
Java bridge route=Some(SingleStatic) selector=Some(ReceiverMember) = Some(SingleTypeImport)
Java bridge route=Some(SingleStatic) selector=None = Some(SingleTypeImport)
Java bridge route=Some(StaticOnDemand) selector=Some(Named) = Some(OnDemandImport)
Java bridge route=Some(StaticOnDemand) selector=Some(Star) = Some(OnDemandImport)
Java bridge route=Some(StaticOnDemand) selector=Some(ReceiverMember) = Some(OnDemandImport)
Java bridge route=Some(StaticOnDemand) selector=None = Some(OnDemandImport)
Java bridge route=Some(Named) selector=Some(Named) = Some(ExplicitImport)
Java bridge route=Some(Named) selector=Some(Star) = Some(WildcardImport)
Java bridge route=Some(Named) selector=Some(ReceiverMember) = None
Java bridge route=Some(Named) selector=None = None
Java bridge route=Some(Star) selector=Some(Named) = Some(ExplicitImport)
Java bridge route=Some(Star) selector=Some(Star) = Some(WildcardImport)
Java bridge route=Some(Star) selector=Some(ReceiverMember) = None
Java bridge route=Some(Star) selector=None = None
Java bridge route=None selector=Some(Named) = Some(ExplicitImport)
Java bridge route=None selector=Some(Star) = Some(WildcardImport)
Java bridge route=None selector=Some(ReceiverMember) = None
Java bridge route=None selector=None = None
Java lexical-import-head = None
Kotlin origin LocalOrInherited = Some(0)
Kotlin origin ExplicitImport = Some(1)
Kotlin origin WildcardImport = Some(3)
Kotlin origin SameCompilationUnitPackage = Some(2)
Kotlin origin OtherCompilationUnitPackage = None
Kotlin origin SingleTypeImport = None
Kotlin origin OnDemandImport = Some(3)
Kotlin origin SamePackage = Some(2)
Kotlin origin StarImport = Some(3)
Kotlin origin RootPackage = Some(4)
Kotlin origin DefaultImport = Some(4)
Kotlin root Named = ExplicitImport
Kotlin root Glob = StarImport
Kotlin package SamePackage = Some(PackageOrModule) SamePackage
Kotlin package OtherPackage = Some(DefaultImport) StarImport
Kotlin assembly full-route selector=Some(Named) = ExplicitImport
Kotlin assembly full-route selector=Some(Star) = StarImport
Kotlin assembly full-route selector=Some(ReceiverMember) = OtherCompilationUnitPackage
Kotlin assembly full-route selector=None = OtherCompilationUnitPackage
Kotlin assembly package-prefix-same-unit selector=Some(Named) = ExplicitImport
Kotlin assembly package-prefix-same-unit selector=Some(Star) = StarImport
Kotlin assembly package-prefix-same-unit selector=Some(ReceiverMember) = OtherCompilationUnitPackage
Kotlin assembly package-prefix-same-unit selector=None = OtherCompilationUnitPackage
Kotlin assembly package-prefix-other-unit selector=Some(Named) = ExplicitImport
Kotlin assembly package-prefix-other-unit selector=Some(Star) = StarImport
Kotlin assembly package-prefix-other-unit selector=Some(ReceiverMember) = OtherCompilationUnitPackage
Kotlin assembly package-prefix-other-unit selector=None = OtherCompilationUnitPackage
Kotlin assembly package-prefix-unknown-unit selector=Some(Named) = ExplicitImport
Kotlin assembly package-prefix-unknown-unit selector=Some(Star) = StarImport
Kotlin assembly package-prefix-unknown-unit selector=Some(ReceiverMember) = OtherCompilationUnitPackage
Kotlin assembly package-prefix-unknown-unit selector=None = OtherCompilationUnitPackage
Kotlin bridge route=Some(SingleType) selector=Some(Named) = Some(SingleTypeImport)
Kotlin bridge route=Some(SingleType) selector=Some(Star) = Some(SingleTypeImport)
Kotlin bridge route=Some(SingleType) selector=Some(ReceiverMember) = Some(SingleTypeImport)
Kotlin bridge route=Some(SingleType) selector=None = Some(SingleTypeImport)
Kotlin bridge route=Some(TypeOnDemand) selector=Some(Named) = Some(OnDemandImport)
Kotlin bridge route=Some(TypeOnDemand) selector=Some(Star) = Some(OnDemandImport)
Kotlin bridge route=Some(TypeOnDemand) selector=Some(ReceiverMember) = Some(OnDemandImport)
Kotlin bridge route=Some(TypeOnDemand) selector=None = Some(OnDemandImport)
Kotlin bridge route=Some(SingleStatic) selector=Some(Named) = Some(SingleTypeImport)
Kotlin bridge route=Some(SingleStatic) selector=Some(Star) = Some(SingleTypeImport)
Kotlin bridge route=Some(SingleStatic) selector=Some(ReceiverMember) = Some(SingleTypeImport)
Kotlin bridge route=Some(SingleStatic) selector=None = Some(SingleTypeImport)
Kotlin bridge route=Some(StaticOnDemand) selector=Some(Named) = Some(OnDemandImport)
Kotlin bridge route=Some(StaticOnDemand) selector=Some(Star) = Some(OnDemandImport)
Kotlin bridge route=Some(StaticOnDemand) selector=Some(ReceiverMember) = Some(OnDemandImport)
Kotlin bridge route=Some(StaticOnDemand) selector=None = Some(OnDemandImport)
Kotlin bridge route=Some(Named) selector=Some(Named) = Some(ExplicitImport)
Kotlin bridge route=Some(Named) selector=Some(Star) = Some(StarImport)
Kotlin bridge route=Some(Named) selector=Some(ReceiverMember) = None
Kotlin bridge route=Some(Named) selector=None = None
Kotlin bridge route=Some(Star) selector=Some(Named) = Some(ExplicitImport)
Kotlin bridge route=Some(Star) selector=Some(Star) = Some(StarImport)
Kotlin bridge route=Some(Star) selector=Some(ReceiverMember) = None
Kotlin bridge route=Some(Star) selector=None = None
Kotlin bridge route=None selector=Some(Named) = Some(ExplicitImport)
Kotlin bridge route=None selector=Some(Star) = Some(StarImport)
Kotlin bridge route=None selector=Some(ReceiverMember) = None
Kotlin bridge route=None selector=None = None
Kotlin lexical-import-head = None
Scala origin LocalOrInherited = Some(0)
Scala origin ExplicitImport = Some(1)
Scala origin WildcardImport = Some(2)
Scala origin SameCompilationUnitPackage = Some(0)
Scala origin OtherCompilationUnitPackage = Some(3)
Scala origin SingleTypeImport = None
Scala origin OnDemandImport = None
Scala origin SamePackage = None
Scala origin StarImport = Some(2)
Scala origin RootPackage = Some(4)
Scala origin DefaultImport = Some(4)
Scala root Named = ExplicitImport
Scala root Glob = WildcardImport
Scala package SamePackage = None OtherCompilationUnitPackage
Scala package OtherPackage = None OtherCompilationUnitPackage
Scala assembly full-route selector=Some(Named) = ExplicitImport
Scala assembly full-route selector=Some(Star) = WildcardImport
Scala assembly full-route selector=Some(ReceiverMember) = OtherCompilationUnitPackage
Scala assembly full-route selector=None = OtherCompilationUnitPackage
Scala assembly package-prefix-same-unit selector=Some(Named) = SameCompilationUnitPackage
Scala assembly package-prefix-same-unit selector=Some(Star) = SameCompilationUnitPackage
Scala assembly package-prefix-same-unit selector=Some(ReceiverMember) = SameCompilationUnitPackage
Scala assembly package-prefix-same-unit selector=None = SameCompilationUnitPackage
Scala assembly package-prefix-other-unit selector=Some(Named) = OtherCompilationUnitPackage
Scala assembly package-prefix-other-unit selector=Some(Star) = OtherCompilationUnitPackage
Scala assembly package-prefix-other-unit selector=Some(ReceiverMember) = OtherCompilationUnitPackage
Scala assembly package-prefix-other-unit selector=None = OtherCompilationUnitPackage
Scala assembly package-prefix-unknown-unit selector=Some(Named) = OtherCompilationUnitPackage
Scala assembly package-prefix-unknown-unit selector=Some(Star) = OtherCompilationUnitPackage
Scala assembly package-prefix-unknown-unit selector=Some(ReceiverMember) = OtherCompilationUnitPackage
Scala assembly package-prefix-unknown-unit selector=None = OtherCompilationUnitPackage
Scala bridge route=Some(SingleType) selector=Some(Named) = Some(SingleTypeImport)
Scala bridge route=Some(SingleType) selector=Some(Star) = Some(SingleTypeImport)
Scala bridge route=Some(SingleType) selector=Some(ReceiverMember) = Some(SingleTypeImport)
Scala bridge route=Some(SingleType) selector=None = Some(SingleTypeImport)
Scala bridge route=Some(TypeOnDemand) selector=Some(Named) = Some(OnDemandImport)
Scala bridge route=Some(TypeOnDemand) selector=Some(Star) = Some(OnDemandImport)
Scala bridge route=Some(TypeOnDemand) selector=Some(ReceiverMember) = Some(OnDemandImport)
Scala bridge route=Some(TypeOnDemand) selector=None = Some(OnDemandImport)
Scala bridge route=Some(SingleStatic) selector=Some(Named) = Some(SingleTypeImport)
Scala bridge route=Some(SingleStatic) selector=Some(Star) = Some(SingleTypeImport)
Scala bridge route=Some(SingleStatic) selector=Some(ReceiverMember) = Some(SingleTypeImport)
Scala bridge route=Some(SingleStatic) selector=None = Some(SingleTypeImport)
Scala bridge route=Some(StaticOnDemand) selector=Some(Named) = Some(OnDemandImport)
Scala bridge route=Some(StaticOnDemand) selector=Some(Star) = Some(OnDemandImport)
Scala bridge route=Some(StaticOnDemand) selector=Some(ReceiverMember) = Some(OnDemandImport)
Scala bridge route=Some(StaticOnDemand) selector=None = Some(OnDemandImport)
Scala bridge route=Some(Named) selector=Some(Named) = Some(ExplicitImport)
Scala bridge route=Some(Named) selector=Some(Star) = Some(WildcardImport)
Scala bridge route=Some(Named) selector=Some(ReceiverMember) = None
Scala bridge route=Some(Named) selector=None = None
Scala bridge route=Some(Star) selector=Some(Named) = Some(ExplicitImport)
Scala bridge route=Some(Star) selector=Some(Star) = Some(WildcardImport)
Scala bridge route=Some(Star) selector=Some(ReceiverMember) = None
Scala bridge route=Some(Star) selector=None = None
Scala bridge route=None selector=Some(Named) = Some(ExplicitImport)
Scala bridge route=None selector=Some(Star) = Some(WildcardImport)
Scala bridge route=None selector=Some(ReceiverMember) = None
Scala bridge route=None selector=None = None
Scala lexical-import-head = Some(RootPackage)
";
        assert_eq!(expected, rendered);
    }
}
