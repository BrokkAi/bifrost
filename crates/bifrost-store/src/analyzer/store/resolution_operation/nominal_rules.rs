//! Language and family rules for demand-local nominal package composition.

use super::jvm_context::JAVA_IMPORT_TARGET_MOUNTS;
use super::jvm_context::{JVM_ELIGIBLE_IMPORT_TARGET_MOUNTS, JVM_IMPORT_TARGET_MOUNTS};
use brokk_bifrost_core::analyzer::Language;

/// A mount selector and the language parameters describing its target set.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ImportTargetMounts {
    pub statement: &'static str,
    pub languages: [Option<&'static str>; 3],
}

pub(in crate::analyzer) trait NominalPackageRules: Sync + 'static {
    fn languages(&self) -> &'static [Language];
    fn storage_languages(&self) -> &'static [&'static str];
    fn storage_language_parameters(&self) -> [Option<&'static str>; 3] {
        let labels = self.storage_languages();
        assert!(labels.len() <= 3, "mount SQL has three language parameters");
        std::array::from_fn(|index| labels.get(index).copied())
    }
    fn admits(&self, language: Language) -> bool {
        self.languages().contains(&language)
    }
    fn admits_storage(&self, storage_language: &str) -> bool {
        self.storage_languages().contains(&storage_language)
    }
    fn import_target_mounts(&self) -> ImportTargetMounts;
    fn eligible_import_target_mounts(&self) -> ImportTargetMounts;
    fn eligible_alias_target_mounts(&self, source: Language) -> ImportTargetMounts {
        ImportTargetMounts {
            languages: self.alias_target_languages(source),
            ..self.eligible_import_target_mounts()
        }
    }
    fn eligible_package_alias_target_mounts(&self, source: Language) -> ImportTargetMounts {
        ImportTargetMounts {
            languages: self.package_alias_target_languages(source),
            ..self.eligible_import_target_mounts()
        }
    }
    fn package_prefix_presence_sql(&self) -> &'static str;
    /// Required: provider identities, peer lookups and owner relations for this family.
    fn external_owners(&self) -> &'static ExternalOwnerRelations;
    fn source_domain_sql(&self) -> &'static str;
    fn own_language_target_mounts(&self, language: Language) -> ImportTargetMounts;
    fn alias_target_languages(&self, _source: Language) -> [Option<&'static str>; 3] {
        [None; 3]
    }
    fn package_alias_target_languages(&self, _source: Language) -> [Option<&'static str>; 3] {
        [None; 3]
    }
    fn admits_alias_target(&self, source: Language, target: Language) -> bool {
        self.alias_target_languages(source)
            .contains(&Some(target.config_label()))
    }
    fn admits_package_alias_target(&self, source: Language, target: Language) -> bool {
        self.package_alias_target_languages(source)
            .contains(&Some(target.config_label()))
    }
    fn admits_qualified_type_bridge_source(&self, _source: Language) -> bool {
        false
    }
    /// The mount query for a language's type-member continuation, or None
    /// before adoption. Java static imports can widen it through the selected
    /// target's owner-namespace hook and explicit JVM bridge proof.
    fn member_continuation_mounts(&self, language: Language) -> Option<ImportTargetMounts>;
}

struct JvmPackageRules {
    languages: &'static [Language],
    storage_languages: &'static [&'static str],
}

// Standalone store tests have no linked language-support registry. Admission
// must remain available independently of analyzer registrations.
pub(in crate::analyzer::store) fn nominal_package_rules(
    language: Language,
) -> Option<&'static dyn NominalPackageRules> {
    nominal_language_rules(language).map(|rules| rules.family())
}

static JVM_PACKAGE_RULES: JvmPackageRules = JvmPackageRules {
    languages: &[Language::Java, Language::Kotlin, Language::Scala],
    storage_languages: &["java", "kotlin", "scala"],
};

pub(in crate::analyzer::store) fn nominal_package_rules_for_storage(
    storage_language: &str,
) -> Option<&'static dyn NominalPackageRules> {
    let language = Language::ANALYZABLE
        .into_iter()
        .find(|language| language.config_label() == storage_language)?;
    let family = nominal_package_rules(language)?;
    family.admits_storage(storage_language).then_some(family)
}

// JVM-only Maven reconciliation and diagnostic SQL use this fixed family.
pub(in crate::analyzer::store) fn jvm_package_rules() -> &'static dyn NominalPackageRules {
    nominal_package_rules(Language::Java).expect("Java belongs to the JVM package family")
}

impl NominalPackageRules for JvmPackageRules {
    fn languages(&self) -> &'static [Language] {
        self.languages
    }
    fn storage_languages(&self) -> &'static [&'static str] {
        self.storage_languages
    }
    fn import_target_mounts(&self) -> ImportTargetMounts {
        ImportTargetMounts {
            statement: JVM_IMPORT_TARGET_MOUNTS,
            languages: self.storage_language_parameters(),
        }
    }
    fn eligible_import_target_mounts(&self) -> ImportTargetMounts {
        ImportTargetMounts {
            statement: JVM_ELIGIBLE_IMPORT_TARGET_MOUNTS,
            languages: self.storage_language_parameters(),
        }
    }
    fn own_language_target_mounts(&self, language: Language) -> ImportTargetMounts {
        assert_eq!(
            language,
            Language::Java,
            "only Java adopts own-language package type imports"
        );
        ImportTargetMounts {
            statement: JAVA_IMPORT_TARGET_MOUNTS,
            languages: [Some(language.config_label()), None, None],
        }
    }
    fn external_owners(&self) -> &'static ExternalOwnerRelations {
        &JVM_EXTERNAL_OWNERS
    }
    fn source_domain_sql(&self) -> &'static str {
        JVM_SOURCE_DOMAIN
    }
    fn package_prefix_presence_sql(&self) -> &'static str {
        JVM_PACKAGE_PREFIX_PRESENCE
    }
    fn alias_target_languages(&self, source: Language) -> [Option<&'static str>; 3] {
        assert!(
            self.admits(source),
            "JVM aliases have a JVM source language"
        );
        let mut peers = self
            .languages()
            .iter()
            .copied()
            .zip(self.storage_languages().iter().copied())
            .filter_map(|(language, storage)| (language != source).then_some(storage));
        [peers.next(), peers.next(), peers.next()]
    }
    fn package_alias_target_languages(&self, source: Language) -> [Option<&'static str>; 3] {
        if source == Language::Java {
            self.alias_target_languages(source)
        } else {
            self.storage_language_parameters()
        }
    }
    fn admits_qualified_type_bridge_source(&self, source: Language) -> bool {
        self.admits(source) && source != Language::Java
    }
    fn member_continuation_mounts(&self, language: Language) -> Option<ImportTargetMounts> {
        if !self.admits(language) {
            None
        } else if language == Language::Java {
            Some(self.own_language_target_mounts(language))
        } else {
            Some(self.import_target_mounts())
        }
    }
}

const JVM_SOURCE_DOMAIN: &str = "SELECT DISTINCT bm.content_package, m.storage_language
             FROM temp.selected_resolution_mounts AS m
             JOIN main.blob_meta AS bm ON bm.blob_id=m.blob_id AND bm.is_complete=1
             WHERE m.storage_language IN ('java', 'kotlin', 'scala')
               AND m.persisted_relative_path=?1
               AND (?2 IS NULL OR m.file_version_id=?2)";

const JVM_PACKAGE_PREFIX_PRESENCE: &str = "SELECT EXISTS(
                   SELECT 1 FROM main.workspace_file_package_rows AS package INDEXED BY idx_workspace_file_package_rows_name
                   JOIN temp.selected_resolution_mounts AS mounted ON mounted.file_version_id=package.file_version_id
                   JOIN main.blob_meta AS meta ON meta.blob_id=mounted.blob_id AND meta.is_complete=1
                   WHERE mounted.storage_language IN ('java','kotlin','scala')
                     AND (package.package_name=?1 OR (package.package_name>=?1||'.' AND package.package_name<?1||'/'))
                   UNION ALL
                   SELECT 1 FROM temp.selected_resolution_mounts AS mounted
                   JOIN main.blob_meta AS meta ON meta.blob_id=mounted.blob_id AND meta.is_complete=1
                   WHERE mounted.file_version_id IS NULL AND mounted.storage_language IN ('java','kotlin','scala')
                     AND (meta.content_package=?1 OR (meta.content_package>=?1||'.' AND meta.content_package<?1||'/'))
                 )";

use super::Result;
use super::jvm_context::{
    JvmImportContext, JvmImportContextGap, JvmImportContextGapSpec, record_open_jvm_import_gap,
    record_scoped_jvm_import_gap,
};
use super::{ResolutionRootImportAnchor, SelectedResolutionOperation};
use crate::CancellationToken;
use brokk_bifrost_core::analyzer::resolution_facts::{
    BindingProjectionKind, ResolutionImportRouteKind, ResolutionImportSelectorKind,
    ResolutionMemberKind, ResolutionNamespace, ResolutionRootImportKind, ResolutionSiteKind,
};
use brokk_bifrost_core::analyzer::structural::resolution::PrecedenceTier;

use crate::analyzer::resolution::BindingOrigin;

/// The selected source and target package relation, independent of language.
#[derive(Clone, Copy, Debug)]
pub(in crate::analyzer) enum PackageRelation {
    SamePackage,
    OtherPackage,
}

/// Whether package-route members originate in the selected source compilation unit.
#[derive(Clone, Copy, Debug)]
pub(in crate::analyzer) enum CompilationUnitRelation {
    SameCompilationUnit,
    OtherCompilationUnit,
}

/// The structural route through which common import assembly found a member.
#[derive(Clone, Copy, Debug)]
pub(in crate::analyzer) enum ImportOriginRoute {
    Complete,
    PackagePrefix(CompilationUnitRelation),
}

/// Per-language inputs to the shared nominal-package algorithms.
/// Values are static; no workspace or operation inventory is retained here.
pub(in crate::analyzer) trait NominalLanguageRules: Sync + 'static {
    /// Required identity and family; every nominal language supplies both.
    fn language(&self) -> Language;
    fn family(&self) -> &'static dyn NominalPackageRules;

    /// Required: origin of a named or wildcard root import.
    fn root_import_origin(&self, kind: ResolutionRootImportKind) -> BindingOrigin;
    /// Required: origin of a common-assembly member from a route and selector.
    fn assembled_import_origin(
        &self,
        route: ImportOriginRoute,
        selector: Option<ResolutionImportSelectorKind>,
    ) -> BindingOrigin;
    /// Required: tier and origin of a selected package route.
    fn package_precedence(
        &self,
        relation: PackageRelation,
    ) -> (Option<PrecedenceTier>, BindingOrigin);
    /// Required: origin of an import bridge, including route-kind overrides.
    fn bridge_import_origin(
        &self,
        import_kind: Option<ResolutionImportRouteKind>,
        selector: Option<ResolutionImportSelectorKind>,
    ) -> Option<BindingOrigin>;
    /// Required: lexical import heads' package-origin override, or None when absent.
    fn lexical_import_head_origin(&self) -> Option<BindingOrigin>;

    /// # Providers
    /// Required: the package used by an empty unpositioned route.
    fn empty_route_package<'a>(&self, caller: Option<&'a str>) -> Option<&'a str>;
    /// Required: select package exports using explicit mounts, member evidence and result bound.
    fn pure_package_export_provider(&self) -> PurePackageExportProvider;
    /// Required: qualified-type bridge authority; the algorithms stay shared.
    fn qualified_type_bridges(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        half: &crate::analyzer::resolution::SelectedRootPathHalf,
        completion: &crate::analyzer::resolution::ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Option<super::jvm_context::JvmRoutePublication>>;
    /// Required: the language's implicitly imported roots.
    fn implicit_root_providers(
        &self,
    ) -> &'static [crate::analyzer::resolution::JvmImplicitRootProvider];
    /// Required: source languages eligible for the exact package-peer provider.
    fn package_peer_languages(&self) -> &'static [Language];
    /// Required: the package declared by source clauses, or None when absent.
    fn lexical_package(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        blob: i64,
    ) -> Result<Option<String>>;
    /// Required: clause-declared package prefixes for an import, empty when absent.
    fn lexical_import_package_prefixes(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        blob: i64,
        token: super::SemanticId,
    ) -> Result<Vec<String>>;
    /// Feature entry: typed prefix evidence defers member selection; absent by default.
    fn has_typed_prefix_deferral(&self) -> bool {
        false
    }
    /// Feature entry: unqualified type references discover modeled implicit owners.
    fn has_unqualified_implicit_owners(&self) -> bool {
        false
    }
    /// Feature entry: unindexed types keep the single implicit root owner, if any.
    fn unindexed_implicit_owner_package(&self) -> Option<&'static str> {
        None
    }

    /// # Access
    /// Required: declaration visibility policy and its five JVM policy answers.
    fn declaration_access_rules(&self) -> crate::analyzer::resolution::JvmDeclarationAccessRules;
    /// Required: selected declaration-access source; every language states its authority.
    fn declaration_access_source(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        identity: super::SemanticId,
    ) -> Option<std::sync::Arc<dyn crate::analyzer::resolution::SelectedDeclarationAccessSource>>;
    /// Required: evidence anchor for pure-package declaration access.
    fn package_access_anchor(&self) -> PackageAccessAnchor;
    /// Required: source languages whose package needs no directory agreement.
    fn lexical_package_languages(&self) -> &'static [Language];
    /// Required: reverse target policy; algorithms stay shared.
    #[cfg(any(test, feature = "test-support"))]
    fn reverse_target_rules(&self) -> &'static dyn super::jvm_reverse_rows::JvmReverseTargetRules;
    /// Feature entry: selected ownership supplies access endpoints; absent by default.
    fn has_declaration_access_endpoints(&self) -> bool {
        false
    }
    /// Feature entry: lexical templates and companions refine access; absent by default.
    fn has_lexical_access_templates(&self) -> bool {
        false
    }
    /// Feature entry: conventional roots prove implicit project access; absent by default.
    fn has_implicit_project_access(&self) -> bool {
        false
    }
    /// Feature entry: static aliases require access to these facade owner languages.
    fn static_alias_access_languages(&self) -> &'static [Language] {
        &[]
    }
    /// Feature entry: reverse nomination retains lexical access routes; absent by default.
    #[cfg(any(test, feature = "test-support"))]
    fn has_reverse_lexical_access(&self) -> bool {
        false
    }

    /// # Import kinds: context composition and activation.
    /// Required: run the selected forward assembly using shared algorithms.
    fn selected_import_context(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        path: &str,
        lookup: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContext>;
    /// Required: run reverse assembly using shared algorithms.
    fn reverse_import_context(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        path: &str,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContext>;
    /// Required: anchors whose imports can use earlier bindings and enclosing packages.
    /// Every nominal language must state its activation and wildcard chaining semantics.
    fn lexical_import_anchors(&self) -> &'static [ResolutionRootImportAnchor];
    /// Feature entry: legacy route metadata classifies imports; absent by default.
    fn has_legacy_import_routes(&self) -> bool {
        false
    }
    /// Feature entry: implicit provider imports can use shared assembly; absent by default.
    fn has_implicit_import_context(&self) -> bool {
        false
    }

    /// # Import kinds: wildcard and selector semantics.
    /// Required: package-prefix lengths eligible to supply an import owner.
    fn import_owner_prefix_lengths(&self, route: usize, leading: usize) -> [usize; 2];
    /// Required: qualifier namespaces for member traversal.
    fn qualifier_namespace(&self, namespace: ResolutionNamespace) -> ResolutionNamespace;
    /// Required: namespace used for member selection.
    fn selection_namespace(&self, namespace: ResolutionNamespace) -> ResolutionNamespace;
    /// Required: namespace for an intermediate member path segment.
    fn intermediate_member_namespace(&self, namespace: ResolutionNamespace) -> ResolutionNamespace;
    /// Required: namespace in which an imported type's owner is read.
    fn import_owner_namespace(&self) -> ResolutionNamespace;
    /// Required: site kinds that supply a type-or-value qualifier.
    fn qualifier_site_kinds(&self) -> &'static [ResolutionSiteKind];
    /// Required: declared member kinds admitted in each namespace.
    fn member_kinds(&self, namespace: ResolutionNamespace) -> &'static [ResolutionMemberKind];
    /// Feature entry: singleton objects additionally bind as values; absent by default.
    fn has_singleton_import_values(&self) -> bool {
        false
    }
    /// Feature entry: callable imports can bind fields and class call roles; absent by default.
    fn has_callable_import_values(&self) -> bool {
        false
    }
    /// Feature entry: static imports read these peer owner namespaces; no peers by default.
    fn static_import_owner_languages(
        &self,
        _kind: Option<ResolutionImportRouteKind>,
    ) -> &'static [Language] {
        &[]
    }

    /// # Import kinds: aliases and facades.
    /// Feature entry: value projections can supply indirect qualifier identities; absent by default.
    fn has_projected_value_qualifiers(&self) -> bool {
        false
    }
    /// Required: projection kinds eligible to provide a qualifier.
    fn qualifier_projection_kinds(&self) -> &'static [BindingProjectionKind];
    /// Required: normalized declared name for member comparison.
    fn member_name<'a>(&self, selected: &'a str) -> &'a str;

    /// # Import kinds: import-gap discharge. Access gaps belong to source access.
    /// Required: record selector or alias uncertainty at the language's import boundary.
    /// Both recording algorithms are shared; every language must select its authority.
    fn record_import_gap(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        spec: JvmImportContextGapSpec,
        gaps: &mut Vec<JvmImportContextGap>,
        inventory_open: &mut bool,
        cancellation: &CancellationToken,
    ) -> Result<()>;
    /// Feature entry: context inventory carries unresolved imports; absent by default.
    fn has_context_import_inventory(&self) -> bool {
        false
    }
    /// Feature entry: package member inventories supply completion evidence; absent by default.
    fn has_package_member_inventory(&self) -> bool {
        false
    }
}

/// The selected evidence that anchors package-member access.
#[derive(Clone, Copy)]
pub(in crate::analyzer) enum PackageAccessAnchor {
    ImportToken,
    LexicalSource,
}

type RecordImportGap = for<'a, 'b> fn(
    &SelectedResolutionOperation<'a, 'b>,
    JvmImportContextGapSpec,
    &mut Vec<JvmImportContextGap>,
    &mut bool,
    &CancellationToken,
) -> Result<()>;

type SelectedImportContext = for<'a, 'b> fn(
    &dyn NominalLanguageRules,
    &SelectedResolutionOperation<'a, 'b>,
    &str,
    Option<&str>,
    &CancellationToken,
) -> Result<JvmImportContext>;
type ReverseImportContext = for<'a, 'b> fn(
    &dyn NominalLanguageRules,
    &SelectedResolutionOperation<'a, 'b>,
    &str,
    &CancellationToken,
) -> Result<JvmImportContext>;

/// Inputs to the shared package-export traversal. A missing member reader
/// leaves exports unrestricted by package-member rows; a bound stops discovery.
#[derive(Clone, Copy)]
pub(in crate::analyzer) struct PurePackageExportProvider {
    pub mounts: ImportTargetMounts,
    pub members: Option<PackageExportMembers>,
    pub result_bound: Option<usize>,
}

type PackageExportMembers = for<'a, 'b> fn(
    &SelectedResolutionOperation<'a, 'b>,
    super::SelectedResolutionMountOrdinal,
    super::SemanticId,
    &CancellationToken,
) -> Result<
    Option<std::sync::Arc<[crate::analyzer::resolution::LoweredPackageMember]>>,
>;

type QualifiedTypeBridges =
    for<'a, 'b> fn(
        &SelectedResolutionOperation<'a, 'b>,
        Language,
        &crate::analyzer::resolution::SelectedRootPathHalf,
        &crate::analyzer::resolution::ResolutionCompletion,
        &CancellationToken,
    ) -> Result<Option<super::jvm_context::JvmRoutePublication>>;

struct JvmLanguageRules {
    named_import_origin: BindingOrigin,
    wildcard_import_origin: BindingOrigin,
    star_selector_origin: BindingOrigin,
    package_prefix_origins: Option<(BindingOrigin, BindingOrigin)>,
    same_package_precedence: (Option<PrecedenceTier>, BindingOrigin),
    other_package_precedence: (Option<PrecedenceTier>, BindingOrigin),
    lexical_import_head_origin: Option<BindingOrigin>,
    empty_route_package: for<'a> fn(Option<&'a str>) -> Option<&'a str>,
    export_members: Option<PackageExportMembers>,
    export_bound: Option<usize>,
    export_mounts: fn() -> ImportTargetMounts,
    qualified_bridges: QualifiedTypeBridges,
    package_peers: &'static [Language],
    lexical_package:
        for<'a, 'b> fn(&SelectedResolutionOperation<'a, 'b>, i64) -> Result<Option<String>>,
    lexical_import_package_prefixes: for<'a, 'b> fn(
        &SelectedResolutionOperation<'a, 'b>,
        i64,
        super::SemanticId,
    ) -> Result<Vec<String>>,
    typed_prefix_deferral: bool,
    unqualified_implicit_owners: bool,
    unindexed_implicit_package: Option<&'static str>,
    language: Language,
    selected: SelectedImportContext,
    reverse: ReverseImportContext,
    lexical_import_anchors: &'static [ResolutionRootImportAnchor],
    legacy_routes: bool,
    implicit_context: bool,
    owner_namespace: ResolutionNamespace,
    qualifier_namespaces: &'static [(ResolutionNamespace, ResolutionNamespace)],
    selection_namespaces: &'static [(ResolutionNamespace, ResolutionNamespace)],
    intermediate_namespaces: &'static [(ResolutionNamespace, ResolutionNamespace)],
    qualifier_sites: &'static [ResolutionSiteKind],
    value_members: &'static [ResolutionMemberKind],
    callable_members: &'static [ResolutionMemberKind],
    singleton_values: bool,
    callable_values: bool,
    static_owner_languages: &'static [Language],
    projected_values: bool,
    projections: &'static [BindingProjectionKind],
    member_suffix: Option<&'static str>,
    record_gap: RecordImportGap,
    context_inventory: bool,
    package_inventory: bool,
    access: crate::analyzer::resolution::JvmDeclarationAccessRules,
    access_source: for<'a, 'b> fn(
        &SelectedResolutionOperation<'a, 'b>,
        super::SemanticId,
    ) -> Option<
        std::sync::Arc<dyn crate::analyzer::resolution::SelectedDeclarationAccessSource>,
    >,
    package_access_anchor: PackageAccessAnchor,
    lexical_package_languages: &'static [Language],
    #[cfg(any(test, feature = "test-support"))]
    reverse_target: &'static dyn super::jvm_reverse_rows::JvmReverseTargetRules,
    access_endpoints: bool,
    lexical_access: bool,
    implicit_project_access: bool,
    static_alias_access_languages: &'static [Language],
    #[cfg(any(test, feature = "test-support"))]
    reverse_lexical_access: bool,
}

impl NominalLanguageRules for JvmLanguageRules {
    fn root_import_origin(&self, kind: ResolutionRootImportKind) -> BindingOrigin {
        match kind {
            ResolutionRootImportKind::Named => self.named_import_origin,
            ResolutionRootImportKind::Glob => self.wildcard_import_origin,
        }
    }
    fn assembled_import_origin(
        &self,
        route: ImportOriginRoute,
        selector: Option<ResolutionImportSelectorKind>,
    ) -> BindingOrigin {
        if let (ImportOriginRoute::PackagePrefix(relation), Some((same, other))) =
            (route, self.package_prefix_origins)
        {
            match relation {
                CompilationUnitRelation::SameCompilationUnit => same,
                CompilationUnitRelation::OtherCompilationUnit => other,
            }
        } else {
            match selector {
                Some(ResolutionImportSelectorKind::Named) => self.named_import_origin,
                Some(ResolutionImportSelectorKind::Star) => self.star_selector_origin,
                Some(ResolutionImportSelectorKind::ReceiverMember) | None => {
                    BindingOrigin::OtherCompilationUnitPackage
                }
            }
        }
    }
    fn package_precedence(
        &self,
        relation: PackageRelation,
    ) -> (Option<PrecedenceTier>, BindingOrigin) {
        match relation {
            PackageRelation::SamePackage => self.same_package_precedence,
            PackageRelation::OtherPackage => self.other_package_precedence,
        }
    }
    fn bridge_import_origin(
        &self,
        import_kind: Option<ResolutionImportRouteKind>,
        selector: Option<ResolutionImportSelectorKind>,
    ) -> Option<BindingOrigin> {
        match import_kind {
            Some(
                ResolutionImportRouteKind::SingleType | ResolutionImportRouteKind::SingleStatic,
            ) => Some(BindingOrigin::SingleTypeImport),
            Some(
                ResolutionImportRouteKind::TypeOnDemand | ResolutionImportRouteKind::StaticOnDemand,
            ) => Some(BindingOrigin::OnDemandImport),
            _ => match selector {
                Some(ResolutionImportSelectorKind::Named) => Some(BindingOrigin::ExplicitImport),
                Some(ResolutionImportSelectorKind::Star) => Some(self.star_selector_origin),
                Some(ResolutionImportSelectorKind::ReceiverMember) | None => None,
            },
        }
    }
    fn lexical_import_head_origin(&self) -> Option<BindingOrigin> {
        self.lexical_import_head_origin
    }
    fn empty_route_package<'a>(&self, caller: Option<&'a str>) -> Option<&'a str> {
        (self.empty_route_package)(caller)
    }
    fn pure_package_export_provider(&self) -> PurePackageExportProvider {
        PurePackageExportProvider {
            mounts: (self.export_mounts)(),
            members: self.export_members,
            result_bound: self.export_bound,
        }
    }
    fn qualified_type_bridges(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        half: &crate::analyzer::resolution::SelectedRootPathHalf,
        completion: &crate::analyzer::resolution::ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Option<super::jvm_context::JvmRoutePublication>> {
        (self.qualified_bridges)(operation, self.language, half, completion, cancellation)
    }
    fn implicit_root_providers(
        &self,
    ) -> &'static [crate::analyzer::resolution::JvmImplicitRootProvider] {
        crate::analyzer::resolution::language_implicit_root_providers(self.language)
    }
    fn package_peer_languages(&self) -> &'static [Language] {
        self.package_peers
    }
    fn lexical_package(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        blob: i64,
    ) -> Result<Option<String>> {
        (self.lexical_package)(operation, blob)
    }
    fn lexical_import_package_prefixes(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        blob: i64,
        token: super::SemanticId,
    ) -> Result<Vec<String>> {
        (self.lexical_import_package_prefixes)(operation, blob, token)
    }
    fn has_typed_prefix_deferral(&self) -> bool {
        self.typed_prefix_deferral
    }
    fn has_unqualified_implicit_owners(&self) -> bool {
        self.unqualified_implicit_owners
    }
    fn unindexed_implicit_owner_package(&self) -> Option<&'static str> {
        self.unindexed_implicit_package
    }

    fn language(&self) -> Language {
        self.language
    }
    fn family(&self) -> &'static dyn NominalPackageRules {
        &JVM_PACKAGE_RULES
    }
    fn declaration_access_rules(&self) -> crate::analyzer::resolution::JvmDeclarationAccessRules {
        self.access
    }
    fn declaration_access_source(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        identity: super::SemanticId,
    ) -> Option<std::sync::Arc<dyn crate::analyzer::resolution::SelectedDeclarationAccessSource>>
    {
        (self.access_source)(operation, identity)
    }
    fn package_access_anchor(&self) -> PackageAccessAnchor {
        self.package_access_anchor
    }
    fn lexical_package_languages(&self) -> &'static [Language] {
        self.lexical_package_languages
    }
    #[cfg(any(test, feature = "test-support"))]
    fn reverse_target_rules(&self) -> &'static dyn super::jvm_reverse_rows::JvmReverseTargetRules {
        self.reverse_target
    }
    fn has_declaration_access_endpoints(&self) -> bool {
        self.access_endpoints
    }
    fn has_lexical_access_templates(&self) -> bool {
        self.lexical_access
    }
    fn has_implicit_project_access(&self) -> bool {
        self.implicit_project_access
    }
    fn static_alias_access_languages(&self) -> &'static [Language] {
        self.static_alias_access_languages
    }
    #[cfg(any(test, feature = "test-support"))]
    fn has_reverse_lexical_access(&self) -> bool {
        self.reverse_lexical_access
    }
    fn selected_import_context(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        path: &str,
        lookup: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContext> {
        (self.selected)(self, operation, path, lookup, cancellation)
    }
    fn reverse_import_context(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        path: &str,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContext> {
        (self.reverse)(self, operation, path, cancellation)
    }
    fn lexical_import_anchors(&self) -> &'static [ResolutionRootImportAnchor] {
        self.lexical_import_anchors
    }
    fn has_legacy_import_routes(&self) -> bool {
        self.legacy_routes
    }
    fn has_implicit_import_context(&self) -> bool {
        self.implicit_context
    }
    fn import_owner_prefix_lengths(&self, route: usize, leading: usize) -> [usize; 2] {
        [
            route,
            if self
                .lexical_import_anchors
                .contains(&ResolutionRootImportAnchor::Lexical)
                || leading == 0
            {
                route
            } else {
                leading
            },
        ]
    }
    fn qualifier_namespace(&self, namespace: ResolutionNamespace) -> ResolutionNamespace {
        self.qualifier_namespaces
            .iter()
            .find_map(|(source, target)| (*source == namespace).then_some(*target))
            .unwrap_or(namespace)
    }
    fn selection_namespace(&self, namespace: ResolutionNamespace) -> ResolutionNamespace {
        self.selection_namespaces
            .iter()
            .find_map(|(source, target)| (*source == namespace).then_some(*target))
            .unwrap_or(namespace)
    }
    fn intermediate_member_namespace(&self, namespace: ResolutionNamespace) -> ResolutionNamespace {
        self.intermediate_namespaces
            .iter()
            .find_map(|(source, target)| (*source == namespace).then_some(*target))
            .unwrap_or(namespace)
    }
    fn import_owner_namespace(&self) -> ResolutionNamespace {
        self.owner_namespace
    }
    fn qualifier_site_kinds(&self) -> &'static [ResolutionSiteKind] {
        self.qualifier_sites
    }
    fn member_kinds(&self, namespace: ResolutionNamespace) -> &'static [ResolutionMemberKind] {
        use ResolutionMemberKind::*;
        match namespace {
            ResolutionNamespace::Type => &[NestedType, AssociatedType],
            ResolutionNamespace::Value => self.value_members,
            ResolutionNamespace::TypeOrValue => &[NestedType, AssociatedType, Field],
            ResolutionNamespace::Callable => self.callable_members,
            _ => &[],
        }
    }
    fn has_singleton_import_values(&self) -> bool {
        self.singleton_values
    }
    fn has_callable_import_values(&self) -> bool {
        self.callable_values
    }
    fn static_import_owner_languages(
        &self,
        kind: Option<ResolutionImportRouteKind>,
    ) -> &'static [Language] {
        match kind {
            Some(
                ResolutionImportRouteKind::SingleStatic | ResolutionImportRouteKind::StaticOnDemand,
            ) => self.static_owner_languages,
            _ => &[],
        }
    }
    fn has_projected_value_qualifiers(&self) -> bool {
        self.projected_values
    }
    fn qualifier_projection_kinds(&self) -> &'static [BindingProjectionKind] {
        self.projections
    }
    fn member_name<'a>(&self, selected: &'a str) -> &'a str {
        self.member_suffix
            .and_then(|suffix| selected.strip_suffix(suffix))
            .unwrap_or(selected)
    }
    fn record_import_gap(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        spec: JvmImportContextGapSpec,
        gaps: &mut Vec<JvmImportContextGap>,
        inventory_open: &mut bool,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        (self.record_gap)(operation, spec, gaps, inventory_open, cancellation)
    }
    fn has_context_import_inventory(&self) -> bool {
        self.context_inventory
    }
    fn has_package_member_inventory(&self) -> bool {
        self.package_inventory
    }
}

pub(in crate::analyzer) fn nominal_language_rules(
    language: Language,
) -> Option<&'static dyn NominalLanguageRules> {
    match language {
        Language::Java => Some(&JAVA_RULES),
        Language::Kotlin => Some(&KOTLIN_RULES),
        Language::Scala => Some(&SCALA_RULES),
        _ => None,
    }
}

static JAVA_RULES: JvmLanguageRules = JvmLanguageRules {
    named_import_origin: BindingOrigin::SingleTypeImport,
    wildcard_import_origin: BindingOrigin::OnDemandImport,
    star_selector_origin: BindingOrigin::WildcardImport,
    package_prefix_origins: None,
    same_package_precedence: (None, BindingOrigin::SamePackage),
    other_package_precedence: (None, BindingOrigin::OtherCompilationUnitPackage),
    lexical_import_head_origin: None,
    empty_route_package: absolute_empty_route_package,
    export_members: None,
    export_bound: Some(1),
    export_mounts: exact_package_export_mounts,
    qualified_bridges: |operation, language, half, completion, cancellation| {
        operation.java_qualified_type_publication(language, half, completion, cancellation)
    },
    package_peers: &[Language::Java],
    lexical_package: |_, _| Ok(None),
    lexical_import_package_prefixes: |_, _, _| Ok(Vec::new()),
    typed_prefix_deferral: true,
    unqualified_implicit_owners: true,
    unindexed_implicit_package: Some("java.lang"),

    language: Language::Java,
    access: crate::analyzer::resolution::JvmDeclarationAccessRules::Java,
    access_source: no_declaration_access_source,
    package_access_anchor: PackageAccessAnchor::ImportToken,
    lexical_package_languages: &[],
    #[cfg(any(test, feature = "test-support"))]
    reverse_target: &super::jvm_reverse_rows::JavaReverseTargetRules,
    access_endpoints: true,
    lexical_access: false,
    implicit_project_access: false,
    static_alias_access_languages: &[Language::Kotlin],
    #[cfg(any(test, feature = "test-support"))]
    reverse_lexical_access: false,
    selected: selected_java_import_context,
    reverse: reverse_java_import_context,
    lexical_import_anchors: &[],
    legacy_routes: true,
    implicit_context: false,
    owner_namespace: ResolutionNamespace::Type,
    qualifier_namespaces: &[],
    selection_namespaces: &[],
    intermediate_namespaces: &[],
    qualifier_sites: &[ResolutionSiteKind::ValueReference],
    value_members: &[ResolutionMemberKind::Field],
    callable_members: &[ResolutionMemberKind::Method],
    singleton_values: false,
    callable_values: false,
    static_owner_languages: &[Language::Java, Language::Kotlin, Language::Scala],
    projected_values: false,
    projections: &[
        BindingProjectionKind::TargetTypeOrDeclaredValueType,
        BindingProjectionKind::TargetTypeIdentity,
    ],
    member_suffix: None,
    record_gap: record_open_jvm_import_gap,
    context_inventory: true,
    package_inventory: false,
};

static KOTLIN_RULES: JvmLanguageRules = JvmLanguageRules {
    named_import_origin: BindingOrigin::ExplicitImport,
    wildcard_import_origin: BindingOrigin::StarImport,
    star_selector_origin: BindingOrigin::StarImport,
    package_prefix_origins: None,
    same_package_precedence: (
        Some(PrecedenceTier::PackageOrModule),
        BindingOrigin::SamePackage,
    ),
    other_package_precedence: (
        Some(PrecedenceTier::DefaultImport),
        BindingOrigin::StarImport,
    ),
    lexical_import_head_origin: None,
    empty_route_package: caller_empty_route_package,
    export_members: Some(selected_package_export_members),
    export_bound: None,
    export_mounts: family_package_export_mounts,
    qualified_bridges: |operation, language, half, completion, cancellation| {
        operation.common_qualified_type_publication(language, half, completion, cancellation)
    },
    package_peers: &[Language::Kotlin],
    lexical_package: |_, _| Ok(None),
    lexical_import_package_prefixes: |_, _, _| Ok(Vec::new()),
    typed_prefix_deferral: false,
    unqualified_implicit_owners: false,
    unindexed_implicit_package: None,

    language: Language::Kotlin,
    access: crate::analyzer::resolution::JvmDeclarationAccessRules::Kotlin,
    access_source: selected_declaration_access_source,
    package_access_anchor: PackageAccessAnchor::LexicalSource,
    lexical_package_languages: &[Language::Kotlin],
    #[cfg(any(test, feature = "test-support"))]
    reverse_target: &super::jvm_reverse_rows::KotlinReverseTargetRules,
    access_endpoints: false,
    lexical_access: false,
    implicit_project_access: true,
    static_alias_access_languages: &[],
    #[cfg(any(test, feature = "test-support"))]
    reverse_lexical_access: false,
    selected: selected_common_import_context,
    reverse: reverse_common_import_context,
    lexical_import_anchors: &[],
    legacy_routes: false,
    implicit_context: true,
    owner_namespace: ResolutionNamespace::Type,
    qualifier_namespaces: &[],
    selection_namespaces: &[],
    intermediate_namespaces: &[],
    qualifier_sites: &[ResolutionSiteKind::ValueReference],
    value_members: &[ResolutionMemberKind::Field],
    callable_members: &[ResolutionMemberKind::Method],
    singleton_values: false,
    callable_values: false,
    static_owner_languages: &[],
    projected_values: false,
    projections: &[
        BindingProjectionKind::TargetTypeOrDeclaredValueType,
        BindingProjectionKind::TargetTypeIdentity,
    ],
    member_suffix: None,
    record_gap: record_scoped_jvm_import_gap,
    context_inventory: false,
    package_inventory: true,
};

static SCALA_RULES: JvmLanguageRules = JvmLanguageRules {
    named_import_origin: BindingOrigin::ExplicitImport,
    wildcard_import_origin: BindingOrigin::WildcardImport,
    star_selector_origin: BindingOrigin::WildcardImport,
    package_prefix_origins: Some((
        BindingOrigin::SameCompilationUnitPackage,
        BindingOrigin::OtherCompilationUnitPackage,
    )),
    same_package_precedence: (None, BindingOrigin::OtherCompilationUnitPackage),
    other_package_precedence: (None, BindingOrigin::OtherCompilationUnitPackage),
    lexical_import_head_origin: Some(BindingOrigin::RootPackage),
    empty_route_package: caller_empty_route_package,
    export_members: Some(selected_package_export_members),
    export_bound: None,
    export_mounts: family_package_export_mounts,
    qualified_bridges: |operation, language, half, completion, cancellation| {
        operation.common_qualified_type_publication(language, half, completion, cancellation)
    },
    package_peers: &[Language::Scala],
    lexical_package: |operation, blob| operation.scala_primary_package(blob),
    lexical_import_package_prefixes: |operation, blob, token| {
        operation.scala_import_package_prefixes(blob, token)
    },
    typed_prefix_deferral: false,
    unqualified_implicit_owners: false,
    unindexed_implicit_package: None,

    language: Language::Scala,
    access: crate::analyzer::resolution::JvmDeclarationAccessRules::Scala,
    access_source: selected_declaration_access_source,
    package_access_anchor: PackageAccessAnchor::LexicalSource,
    lexical_package_languages: &[Language::Scala],
    #[cfg(any(test, feature = "test-support"))]
    reverse_target: &super::jvm_reverse_rows::ScalaReverseTargetRules,
    access_endpoints: true,
    lexical_access: true,
    implicit_project_access: true,
    static_alias_access_languages: &[],
    #[cfg(any(test, feature = "test-support"))]
    reverse_lexical_access: true,
    selected: selected_common_import_context,
    reverse: reverse_common_import_context,
    lexical_import_anchors: &[ResolutionRootImportAnchor::Lexical],
    legacy_routes: false,
    implicit_context: true,
    owner_namespace: ResolutionNamespace::Value,
    qualifier_namespaces: &[
        (ResolutionNamespace::Type, ResolutionNamespace::Value),
        (ResolutionNamespace::TypeOrValue, ResolutionNamespace::Value),
    ],
    selection_namespaces: &[(ResolutionNamespace::Callable, ResolutionNamespace::Value)],
    intermediate_namespaces: &[(ResolutionNamespace::Type, ResolutionNamespace::TypeOrValue)],
    qualifier_sites: &[
        ResolutionSiteKind::ValueReference,
        ResolutionSiteKind::ImportQualifierReference,
    ],
    value_members: &[
        ResolutionMemberKind::Field,
        ResolutionMemberKind::Method,
        ResolutionMemberKind::NestedType,
    ],
    callable_members: &[
        ResolutionMemberKind::Method,
        ResolutionMemberKind::Field,
        ResolutionMemberKind::NestedType,
    ],
    singleton_values: true,
    callable_values: true,
    static_owner_languages: &[],
    projected_values: true,
    projections: &[
        BindingProjectionKind::TargetTypeOrDeclaredValueType,
        BindingProjectionKind::TargetTypeIdentity,
        BindingProjectionKind::TargetDeclaredValueType,
    ],
    member_suffix: Some("$"),
    record_gap: record_scoped_jvm_import_gap,
    context_inventory: false,
    package_inventory: true,
};

fn selected_java_import_context(
    _rules: &dyn NominalLanguageRules,
    operation: &SelectedResolutionOperation<'_, '_>,
    path: &str,
    lookup: Option<&str>,
    cancellation: &CancellationToken,
) -> Result<JvmImportContext> {
    operation
        .selected_java_import_context_with_jvm_peers(path, lookup, cancellation)
        .map(JvmImportContext::with_open_inventory_gap)
}
fn reverse_java_import_context(
    _rules: &dyn NominalLanguageRules,
    operation: &SelectedResolutionOperation<'_, '_>,
    path: &str,
    cancellation: &CancellationToken,
) -> Result<JvmImportContext> {
    operation.selected_java_import_context_with_jvm_peers(path, None, cancellation)
}

fn selected_common_import_context(
    rules: &dyn NominalLanguageRules,
    operation: &SelectedResolutionOperation<'_, '_>,
    path: &str,
    lookup: Option<&str>,
    cancellation: &CancellationToken,
) -> Result<JvmImportContext> {
    operation.assemble_jvm_import_context(rules.language(), path, lookup, cancellation)
}
fn reverse_common_import_context(
    rules: &dyn NominalLanguageRules,
    operation: &SelectedResolutionOperation<'_, '_>,
    path: &str,
    cancellation: &CancellationToken,
) -> Result<JvmImportContext> {
    operation.jvm_import_context(rules.language(), path, cancellation)
}

fn no_declaration_access_source(
    _operation: &SelectedResolutionOperation<'_, '_>,
    _identity: super::SemanticId,
) -> Option<std::sync::Arc<dyn crate::analyzer::resolution::SelectedDeclarationAccessSource>> {
    None
}

fn selected_declaration_access_source(
    operation: &SelectedResolutionOperation<'_, '_>,
    identity: super::SemanticId,
) -> Option<std::sync::Arc<dyn crate::analyzer::resolution::SelectedDeclarationAccessSource>> {
    Some(operation.jvm_declaration_access_source(identity))
}

fn absolute_empty_route_package(_: Option<&str>) -> Option<&str> {
    Some("")
}
fn caller_empty_route_package(caller: Option<&str>) -> Option<&str> {
    caller
}
fn exact_package_export_mounts() -> ImportTargetMounts {
    JVM_PACKAGE_RULES.own_language_target_mounts(Language::Java)
}
fn family_package_export_mounts() -> ImportTargetMounts {
    JVM_PACKAGE_RULES.import_target_mounts()
}
fn selected_package_export_members(
    operation: &SelectedResolutionOperation<'_, '_>,
    ordinal: super::SelectedResolutionMountOrdinal,
    lookup: super::SemanticId,
    cancellation: &CancellationToken,
) -> Result<Option<std::sync::Arc<[crate::analyzer::resolution::LoweredPackageMember]>>> {
    match operation.jvm_package_members_for_lookup(ordinal, lookup, cancellation)? {
        super::package_context::SelectedPackageRows::Ready(members) => Ok(Some(members)),
        super::package_context::SelectedPackageRows::Cancelled => Ok(None),
    }
}

const JVM_EXTERNAL_SUPERTYPES: &str = "SELECT edge.ordinal,edge.supertype_fqn,COALESCE((SELECT provider_id FROM jvm_external_owners WHERE owner_fqn=edge.supertype_fqn AND provider_id=?1),(SELECT CASE WHEN count(*)=1 THEN min(provider_id) END FROM jvm_external_owners WHERE owner_fqn=edge.supertype_fqn AND provider_id IN (SELECT value FROM json_each(?5))),?1) FROM jvm_external_owner_supertypes edge JOIN jvm_external_owners inventory USING(provider_id,owner_fqn) WHERE edge.provider_id=?1 AND edge.owner_fqn=?2 AND edge.ordinal>?3 AND edge.provider_id IN (SELECT value FROM json_each(?5)) ORDER BY edge.ordinal LIMIT ?4";

const JVM_EXTERNAL_MEMBERS: &str = "SELECT member.ordinal,member.member_name,member.member_kind,member.visibility,member.is_static FROM jvm_external_owner_members member JOIN jvm_external_owners inventory USING(provider_id,owner_fqn) WHERE member.provider_id=?1 AND member.owner_fqn=?2 AND member.ordinal>?3 AND member.provider_id IN (SELECT value FROM json_each(?5)) ORDER BY member.ordinal LIMIT ?4";

const JVM_EXTERNAL_OWNER_SCOPES: &str = "SELECT 0,callables_complete,values_complete,types_complete,supertypes_complete FROM jvm_external_owners WHERE provider_id=?1 AND owner_fqn=?2 AND 0>?3 AND provider_id IN (SELECT value FROM json_each(?5)) LIMIT ?4";

const JVM_EXTERNAL_CALLABLE_RESULT_OWNERS: &str = "WITH requested AS (
                   SELECT json_extract(value, '$[0]') provider_id,
                          json_extract(value, '$[1]') owner_fqn,
                          json_extract(value, '$[2]') ordinal
                   FROM json_each(?1)
                 )
                 SELECT member.provider_id,member.owner_fqn,member.ordinal,
                        json_extract(member.return_type_jsonb, '$.name'),
                        (SELECT CASE WHEN count(*)=1 THEN min(owner.provider_id) END
                           FROM jvm_external_owners owner
                          WHERE owner.owner_fqn=json_extract(member.return_type_jsonb, '$.name')
                            AND owner.provider_id IN (SELECT value FROM json_each(?2)))
                   FROM requested
                   JOIN jvm_external_owner_members member
                     ON member.provider_id=requested.provider_id
                    AND member.owner_fqn=requested.owner_fqn
                    AND member.ordinal=requested.ordinal
                  WHERE member.member_kind IN ('method','function')
                    AND json_extract(member.return_type_jsonb, '$.kind')='named'
                    AND member.provider_id IN (SELECT value FROM json_each(?2))
                  ORDER BY member.provider_id,member.owner_fqn,member.ordinal";

const JVM_EXTERNAL_DECLARATION_OWNER: &str = "SELECT CASE WHEN count(*)=1 THEN min(provider_id) END FROM main.jvm_external_owners WHERE owner_fqn=?1 AND provider_id IN (SELECT value FROM json_each(?2)) HAVING count(*)>0";

/// Static owner relation and provider-set policy. Owner identities currently
/// originate only in the JVM provider family; no language is inferred from an FQN.
pub(in crate::analyzer) struct ExternalOwnerRelations {
    pub languages: &'static [Language],
    pub member_by_definition: &'static str,
    pub owner_indexed: &'static str,
    pub declaration_signatures: &'static str,
    pub signature_type_owners: &'static str,
    pub inheritance_declarations: &'static str,
    pub supertypes: &'static str,
    pub members: &'static str,
    pub owner_scopes: &'static str,
    pub callable_result_owners: &'static str,
    pub declaration_owner: &'static str,
    pub member_return_type: &'static str,
}

impl ExternalOwnerRelations {
    pub fn providers(&self, analyzer: Option<&dyn super::SelectedAnalyzerServices>) -> Vec<String> {
        analyzer
            .map(|analyzer| analyzer.external_inventory_providers())
            .unwrap_or_default()
    }
}

static JVM_EXTERNAL_OWNERS: ExternalOwnerRelations = ExternalOwnerRelations {
    languages: &[Language::Java, Language::Kotlin, Language::Scala],
    member_by_definition:
        super::super::resolution_typed::external_owners::EXTERNAL_MEMBER_OWNER_BY_DEFINITION_SQL,
    owner_indexed:
        super::super::resolution_typed::external_owners::INTRINSIC_MEMBER_OWNER_INDEXED_SQL,
    declaration_signatures:
        super::super::resolution_typed::external_owners::EXTERNAL_DECLARATION_SIGNATURES_SQL,
    signature_type_owners:
        super::super::resolution_typed::external_owners::EXTERNAL_SIGNATURE_TYPE_OWNERS_SQL,
    inheritance_declarations:
        super::super::resolution_typed::external_owners::EXTERNAL_INHERITANCE_DECLARATIONS_SQL,
    supertypes: JVM_EXTERNAL_SUPERTYPES,
    members: JVM_EXTERNAL_MEMBERS,
    owner_scopes: JVM_EXTERNAL_OWNER_SCOPES,
    callable_result_owners: JVM_EXTERNAL_CALLABLE_RESULT_OWNERS,
    declaration_owner: JVM_EXTERNAL_DECLARATION_OWNER,
    member_return_type: JVM_EXTERNAL_MEMBER_RETURN_TYPE,
};

/// Typed external identities carry their provider coordinate, not a caller
/// language. Their existing JVM-only bridge explicitly selects that relation;
/// language-bearing source requests select it through their own family.
pub(in crate::analyzer::store) fn jvm_external_owner_relations() -> &'static ExternalOwnerRelations
{
    jvm_package_rules().external_owners()
}

const JVM_EXTERNAL_MEMBER_RETURN_TYPE: &str = "SELECT json(return_type_jsonb) FROM jvm_external_owner_members WHERE provider_id=?1 AND owner_fqn=?2 AND ordinal=?3 AND signature_present=1";
