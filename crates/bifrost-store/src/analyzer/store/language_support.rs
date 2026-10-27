//! Language capabilities needed by the store and resolution layers.

pub use crate::analyzer::resolution::registry_vocabulary::{
    TypeComponentProjection, TypeComponentSelection,
};
use crate::analyzer::{Language, ProjectFile};

/// One language's bounded classification of selected module declarations.
pub type ModuleDefinitionProvider =
    fn(
        &dyn crate::analyzer::resolution::SelectedTypedFactSource,
        &[crate::analyzer::resolution::SemanticId],
        &crate::CancellationToken,
    ) -> crate::analyzer::store::Result<Vec<crate::analyzer::resolution::SemanticId>>;

/// Operation-owned namespace classification; implementations retain only bounded
/// exact-read memos for the lifetime of the selected typed source.
pub trait NamespaceDefinitionClassifier {
    fn definitions(
        &self,
        selection: &crate::analyzer::store::resolution_selection::SelectedResolutionMountInventory<
            '_,
        >,
        definitions: &[crate::analyzer::resolution::SemanticId],
        cancellation: &crate::CancellationToken,
    ) -> crate::analyzer::store::Result<Vec<crate::analyzer::resolution::SemanticId>>;
}

pub type NamespaceDefinitionProvider = fn() -> Box<dyn NamespaceDefinitionClassifier>;

pub trait StoreLanguageSupport: Send + Sync {
    /// Go member lookup keeps these namespaces without blocking lexical
    /// names in other namespaces. Other member kinds retain lexical authority.
    fn go_member_definition_namespaces(
        &self,
        _kind: brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind,
    ) -> Option<crate::analyzer::resolution::GoDefinitionNamespaces> {
        None
    }

    /// No provider means typed evaluation never reads module rows for this language.
    fn module_definition_provider(&self) -> Option<ModuleDefinitionProvider> {
        None
    }

    /// No provider means namespace classification performs no language reads.
    fn namespace_definition_provider(&self) -> Option<NamespaceDefinitionProvider> {
        None
    }

    fn has_conditional_type_seeds(&self) -> bool {
        false
    }

    /// Selected, bounded conditional type evidence for one slot. The default
    /// deliberately performs no SQL or identity interning.
    fn selected_conditional_type_seed(
        &self,
        _selection: &crate::analyzer::store::resolution_selection::SelectedResolutionMountInventory<
            '_,
        >,
        _slot: crate::analyzer::resolution::SemanticId,
        _cancellation: &crate::CancellationToken,
    ) -> crate::analyzer::store::Result<Option<crate::analyzer::resolution::ConditionalTypeSeed>>
    {
        Ok(None)
    }

    /// Static member capabilities; the selected source exposes this same table.
    /// Actual hierarchy/access hooks are borrowed from the opted-in provider.
    fn qualified_member_registrations(
        &self,
    ) -> &'static [crate::analyzer::resolution::fact_source::QualifiedMemberRegistration] {
        &[]
    }

    /// Retain language-owned native rows in the selected blob transaction.
    fn publish_native_source_rows(
        &self,
        _tx: &rusqlite::Transaction<'_>,
        _blob: i64,
        _facts: &brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts,
        _cancellation: &crate::CancellationToken,
    ) -> crate::analyzer::store::Result<()> {
        Ok(())
    }

    /// Bounded language-owned inputs for an implicit hierarchy edge.
    /// The default performs no reads.
    fn selected_implicit_base_inputs(
        &self,
        _selection: &crate::analyzer::store::resolution_selection::SelectedResolutionMountInventory<
            '_,
        >,
        _environment: i64,
        _declared_version: Option<(u16, u16)>,
        _owner: crate::analyzer::resolution::SemanticId,
        _cancellation: &crate::CancellationToken,
    ) -> crate::analyzer::store::Result<Option<crate::analyzer::resolution::ImplicitBaseInputs>>
    {
        Ok(None)
    }

    /// Prepare bounded static dependency evidence from already selected snapshots.
    fn selected_dependency_file_evidence(
        &self,
        _root: &std::path::Path,
        _selected: &[(ProjectFile, crate::analyzer::ProjectSourceSnapshot)],
        _limits: &crate::analyzer::semantic_model::DependencyFileEvidenceLimits,
    ) -> crate::analyzer::semantic_model::DependencyFileEvidence {
        crate::analyzer::semantic_model::DependencyFileEvidence::default()
    }
    /// Whether a workspace-relative path is a build configuration input this
    /// language captures by exact bytes (for example go.mod or a Gradle build
    /// file), for the selected configuration and its overlay guards.
    fn is_configuration_input_path(&self, _path: &std::path::Path) -> bool {
        false
    }
    /// Add language-owned metadata inputs found beside selected source files.
    fn include_native_metadata_paths(
        &self,
        _project: &dyn crate::analyzer::Project,
        _files: &std::collections::BTreeSet<ProjectFile>,
        _inputs: &mut std::collections::BTreeSet<ProjectFile>,
    ) -> std::io::Result<()> {
        Ok(())
    }
    /// Derive C# compilation membership rules from one revision's selected
    /// MSBuild configuration inputs, ordered by path. `None` bytes mark an
    /// input the publisher could not admit (over a byte cap). `None` means
    /// this language derives no compilation membership.
    fn csharp_compilation_facts(
        &self,
        _inputs: &[crate::analyzer::store::csharp_compilation::CSharpConfigurationInput],
    ) -> Option<crate::analyzer::store::csharp_compilation::CSharpCompilationFacts> {
        None
    }
    /// This language's reader of the macro rows its producer sealed into a
    /// selected blob, or `None` when the language publishes no macro rows.
    ///
    /// Selected resolution replays macro invocations from persisted rows, and
    /// the rows belong to the producing language, so the operation asks the
    /// mount's support for this reader instead of calling a language module's
    /// storage directly.
    fn selected_macro_source_rows(
        &self,
    ) -> Option<&'static dyn crate::analyzer::store::resolution_operation::SelectedMacroSourceRows>
    {
        None
    }
    /// Provenance of the root anchor proves the complete source-half horizon
    /// for this language. Shared code retains a universal horizon for transient
    /// sources and limits source discovery only, never declaration visibility.
    fn root_source_horizon_follows_provenance(&self) -> bool {
        false
    }
    /// The language-owned argument mapping, applicability, and specificity rules
    /// used by selected call resolution. `None` uses positional mapping only.
    fn call_applicability_adapter(
        &self,
    ) -> Option<&'static dyn crate::analyzer::resolution::CallApplicabilityAdapter> {
        None
    }
    /// Canonical spelling for a constructor over a resolved builtin element.
    /// Shared evaluation owns completion and identity interning.
    fn intrinsic_sequence_type(
        &self,
        _element: crate::analyzer::resolution::universe::UniverseEntry,
        _constructor: brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeConstructorKind,
        _length: Option<&str>,
    ) -> Option<(
        brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind,
        String,
    )> {
        None
    }
    /// Select a component from a structurally identified operand. Shared code
    /// owns named-type traversal, demand, completion and result assembly.
    fn type_component_projection(
        &self,
        transfer: brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeTransferKind,
        constructor: Option<
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeConstructorKind,
        >,
        _intrinsic: Option<crate::analyzer::resolution::universe::UniverseEntry>,
        operand: crate::analyzer::resolution::ResolutionSlotValue,
    ) -> Option<TypeComponentProjection> {
        use brokk_bifrost_core::analyzer::resolution_facts::{
            ResolutionTypeComponentKind as Component, ResolutionTypeConstructorKind as Constructor,
            ResolutionTypeTransferKind as Transfer,
        };
        if operand.ty().indirection() != 0 {
            return None;
        }
        let kind = match (transfer, constructor) {
            (
                Transfer::ComponentValue,
                Some(
                    Constructor::Array
                    | Constructor::Slice
                    | Constructor::Sequence
                    | Constructor::Channel,
                ),
            )
            | (Transfer::ComponentKey, Some(Constructor::Channel)) => Component::Element,
            (Transfer::ComponentElement | Transfer::ComponentKey | Transfer::ComponentValue, _) => {
                transfer.component_kind().expect("component transfer")
            }
            _ => return None,
        };
        Some(TypeComponentProjection {
            selection: TypeComponentSelection::Component(kind),
            addressable: None,
        })
    }
}

/// Link-time language capabilities indexed in the canonical analyzable order.
#[doc(hidden)]
pub type StoreLanguageTable =
    [Option<&'static dyn StoreLanguageSupport>; crate::analyzer::Language::ANALYZABLE.len()];

#[doc(hidden)]
pub fn language_index(language: Language) -> Option<usize> {
    Some(match language {
        Language::None => return None,
        Language::Java => 0,
        Language::Go => 1,
        Language::Cpp => 2,
        Language::JavaScript => 3,
        Language::TypeScript => 4,
        Language::Python => 5,
        Language::Rust => 6,
        Language::Php => 7,
        Language::Scala => 8,
        Language::CSharp => 9,
        Language::Ruby => 10,
        Language::Kotlin => 11,
    })
}

/// One immutable projection of the linked language supports, never an owner or
/// workspace index. Language supports are the only registration authority.
/// Query-local neutral fixture overlays must never seed the immutable table.
pub(crate) fn qualified_member_registrations()
-> &'static [crate::analyzer::resolution::fact_source::QualifiedMemberRegistration] {
    static TABLE: std::sync::OnceLock<
        Box<[crate::analyzer::resolution::fact_source::QualifiedMemberRegistration]>,
    > = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        Language::ANALYZABLE
            .iter()
            .flat_map(|&language| {
                super::linked_store_language_support(language)
                    .into_iter()
                    .flat_map(move |support| {
                        support
                            .qualified_member_registrations()
                            .iter()
                            .copied()
                            .inspect(move |entry| {
                                assert_eq!(
                                    entry.language, language,
                                    "registration belongs to its language support"
                                );
                                assert!(
                                    entry.hierarchy_identity != 0 || entry.member_access,
                                    "default member semantics need no registration"
                                );
                            })
                    })
            })
            .collect()
    })
}

/// Explicit neutral rules for shared-algorithm tests using parsed fixture syntax.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod neutral_fixture {
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        static OVERLAYS: RefCell<Vec<StoreLanguageTable>> = const { RefCell::new(Vec::new()) };
    }

    pub struct NeutralFakeStoreLanguageSupport;
    impl StoreLanguageSupport for NeutralFakeStoreLanguageSupport {
        fn call_applicability_adapter(
            &self,
        ) -> Option<&'static dyn crate::analyzer::resolution::CallApplicabilityAdapter> {
            Some(&NeutralFakeCallApplicabilityAdapter)
        }
    }

    pub struct NeutralFakeCallApplicabilityAdapter;
    impl crate::analyzer::resolution::CallApplicabilityAdapter for NeutralFakeCallApplicabilityAdapter {
        fn map_arguments(
            &self,
            call: &crate::analyzer::resolution::typed_fact_lowering::LoweredCallApplicabilityObligation,
            signature: &crate::analyzer::resolution::typed_fact_lowering::LoweredCallableSignatureProperty,
        ) -> crate::analyzer::resolution::fact_resolution::call_applicability::MappingAssessment
        {
            use crate::analyzer::resolution::fact_resolution::call_applicability::map_call_shape;
            map_call_shape(call, signature, false, false,
                brokk_bifrost_core::analyzer::structural::callable::CallableRejectionReason::ArityBelowRequired)
        }
    }

    /// Drops on the creating thread and restores the enclosing fixture's overlay.
    pub struct NeutralRulesFixture {
        depth: usize,
        _thread: std::marker::PhantomData<std::rc::Rc<()>>,
    }

    /// Register only the fixture languages, without changing the linked table.
    pub fn neutral_rules_fixture(languages: &[Language]) -> NeutralRulesFixture {
        let mut table: StoreLanguageTable = [None; Language::ANALYZABLE.len()];
        for &language in languages {
            let index = language_index(language).expect("neutral fixture requires a language");
            table[index] = Some(&NeutralFakeStoreLanguageSupport);
        }
        let depth = OVERLAYS.with(|overlays| {
            let mut overlays = overlays.borrow_mut();
            overlays.push(table);
            overlays.len()
        });
        NeutralRulesFixture {
            depth,
            _thread: std::marker::PhantomData,
        }
    }

    #[cfg(test)]
    pub(in crate::analyzer::store) fn dependency_overlay_fixture(
        support: &'static dyn StoreLanguageSupport,
    ) -> NeutralRulesFixture {
        let fixture = neutral_rules_fixture(&[Language::Rust]);
        OVERLAYS.with(|overlays| {
            overlays.borrow_mut().last_mut().unwrap()[language_index(Language::Rust).unwrap()] =
                Some(support);
        });
        fixture
    }

    impl Drop for NeutralRulesFixture {
        fn drop(&mut self) {
            OVERLAYS.with(|overlays| {
                let mut overlays = overlays.borrow_mut();
                assert_eq!(
                    overlays.len(),
                    self.depth,
                    "neutral fixture guards must drop in nesting order"
                );
                overlays.pop().expect("live neutral fixture overlay");
            });
        }
    }

    pub(in crate::analyzer::store) fn support(
        language: Language,
    ) -> Option<&'static dyn StoreLanguageSupport> {
        let index = language_index(language)?;
        OVERLAYS.with(|overlays| {
            overlays
                .borrow()
                .iter()
                .rev()
                .find_map(|table| table[index])
        })
    }
}
