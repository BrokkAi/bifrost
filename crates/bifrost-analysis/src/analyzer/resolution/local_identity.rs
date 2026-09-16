//! Immutable content identity recipes, bijective registration, and complete catalogs.

use super::model::{
    BindingFragmentId, BindingNodeId, PartialPathId, PrecedenceStep, SemanticId, StackVariableId,
};
use crate::hash::HashMap;
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ResolutionSemanticIdentitySpace {
    FragmentLocal,
    Shared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ResolutionSemanticIdentity {
    space: ResolutionSemanticIdentitySpace,
    digest: [u8; 32],
}

impl ResolutionSemanticIdentity {
    pub(crate) const fn fragment_local(digest: [u8; 32]) -> Self {
        Self {
            space: ResolutionSemanticIdentitySpace::FragmentLocal,
            digest,
        }
    }

    pub(crate) const fn shared(digest: [u8; 32]) -> Self {
        Self {
            space: ResolutionSemanticIdentitySpace::Shared,
            digest,
        }
    }

    pub(crate) const fn space(self) -> ResolutionSemanticIdentitySpace {
        self.space
    }

    pub(crate) const fn digest(self) -> [u8; 32] {
        self.digest
    }

    pub(crate) fn mount(self, fragment: BindingFragmentId) -> SemanticId {
        match self.space {
            ResolutionSemanticIdentitySpace::FragmentLocal => {
                SemanticId::in_fragment(fragment, &self.digest)
            }
            ResolutionSemanticIdentitySpace::Shared => SemanticId::from_digest(self.digest),
        }
    }
}

/// The canonical source recipe for one effective lookup semantic.
///
/// The semantic language is the analyzer's stable configuration label, not a
/// storage-language or parser-dialect key. The recipe therefore survives
/// remounting and can be written directly to the normalized lookup-recipe
/// relation without trying to invert an opaque semantic digest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ResolutionLookupSemanticRecipe {
    semantic_language: String,
    namespace: ResolutionNamespace,
    spelling: String,
}

impl ResolutionLookupSemanticRecipe {
    pub(crate) fn new(language: Language, namespace: ResolutionNamespace, spelling: &str) -> Self {
        assert_ne!(
            language,
            Language::None,
            "a resolution lookup recipe needs a semantic language"
        );
        assert!(
            matches!(
                namespace,
                ResolutionNamespace::Type
                    | ResolutionNamespace::Value
                    | ResolutionNamespace::Callable
                    | ResolutionNamespace::Constructor
                    | ResolutionNamespace::Macro
                    | ResolutionNamespace::Constant
            ),
            "a resolution lookup recipe needs one effective namespace: {namespace:?}"
        );
        assert!(
            !spelling.is_empty(),
            "a resolution lookup recipe needs a nonempty spelling"
        );
        Self {
            semantic_language: language.config_label().to_owned(),
            namespace,
            spelling: spelling.to_owned(),
        }
    }

    pub(crate) fn semantic_language(&self) -> &str {
        &self.semantic_language
    }

    pub(crate) const fn namespace(&self) -> ResolutionNamespace {
        self.namespace
    }

    pub(crate) fn spelling(&self) -> &str {
        &self.spelling
    }

    pub(crate) fn identity(&self) -> ResolutionSemanticIdentity {
        let mut hasher = CanonicalHasher::new(b"bifrost-resolution-effective-lookup-key:v1");
        hasher.field("language", self.semantic_language.as_bytes());
        hasher.field("namespace", self.namespace.identity_label().as_bytes());
        hasher.field("spelling", self.spelling.as_bytes());
        ResolutionSemanticIdentity::shared(hasher.finish())
    }
}

macro_rules! local_identity {
    ($name:ident, $mounted:ty, $mount:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub(crate) struct $name([u8; 32]);

        impl $name {
            pub(crate) const fn new(digest: [u8; 32]) -> Self {
                Self(digest)
            }

            pub(crate) const fn digest(self) -> [u8; 32] {
                self.0
            }

            pub(crate) fn mount(self, fragment: BindingFragmentId) -> $mounted {
                ($mount)(fragment, &self.0)
            }
        }
    };
}

local_identity!(
    ResolutionNodeIdentity,
    BindingNodeId,
    BindingNodeId::in_fragment
);
local_identity!(
    ResolutionPathIdentity,
    PartialPathId,
    PartialPathId::in_fragment
);
local_identity!(
    ResolutionStackVariableIdentity,
    StackVariableId,
    StackVariableId::in_fragment
);

#[derive(Debug)]
pub(crate) struct ResolutionIdentityCatalogBuilder {
    fragment: BindingFragmentId,
    semantics: HashMap<SemanticId, ResolutionSemanticIdentity>,
    semantics_by_identity: HashMap<ResolutionSemanticIdentity, SemanticId>,
    lookup_recipes: HashMap<SemanticId, ResolutionLookupSemanticRecipe>,
    lookup_semantics_by_recipe: HashMap<ResolutionLookupSemanticRecipe, SemanticId>,
    precedence_namespaces: HashMap<PrecedenceStep, ResolutionNamespace>,
    nodes: HashMap<BindingNodeId, ResolutionNodeIdentity>,
    nodes_by_identity: HashMap<ResolutionNodeIdentity, BindingNodeId>,
    paths: HashMap<PartialPathId, ResolutionPathIdentity>,
    paths_by_identity: HashMap<ResolutionPathIdentity, PartialPathId>,
    stack_variables: HashMap<StackVariableId, ResolutionStackVariableIdentity>,
    stack_variables_by_identity: HashMap<ResolutionStackVariableIdentity, StackVariableId>,
}

impl ResolutionIdentityCatalogBuilder {
    pub(crate) fn new(fragment: BindingFragmentId) -> Self {
        Self {
            fragment,
            semantics: HashMap::default(),
            semantics_by_identity: HashMap::default(),
            lookup_recipes: HashMap::default(),
            lookup_semantics_by_recipe: HashMap::default(),
            precedence_namespaces: HashMap::default(),
            nodes: HashMap::default(),
            nodes_by_identity: HashMap::default(),
            paths: HashMap::default(),
            paths_by_identity: HashMap::default(),
            stack_variables: HashMap::default(),
            stack_variables_by_identity: HashMap::default(),
        }
    }

    pub(crate) const fn fragment(&self) -> BindingFragmentId {
        self.fragment
    }

    pub(crate) fn semantic(&mut self, identity: ResolutionSemanticIdentity) -> SemanticId {
        let mounted = identity.mount(self.fragment);
        register_identity(
            &mut self.semantics,
            &mut self.semantics_by_identity,
            mounted,
            identity,
            "semantic",
        );
        mounted
    }

    pub(crate) fn lookup_semantic(
        &mut self,
        language: Language,
        namespace: ResolutionNamespace,
        spelling: &str,
    ) -> SemanticId {
        let recipe = ResolutionLookupSemanticRecipe::new(language, namespace, spelling);
        let semantic = self.semantic(recipe.identity());
        register_lookup_recipe(
            &mut self.lookup_recipes,
            &mut self.lookup_semantics_by_recipe,
            semantic,
            recipe,
        );
        semantic
    }

    pub(crate) fn register_precedence_namespace(
        &mut self,
        step: PrecedenceStep,
        namespace: ResolutionNamespace,
    ) -> PrecedenceStep {
        assert_ne!(
            namespace,
            ResolutionNamespace::TypeOrValue,
            "a precedence step needs an effective namespace"
        );
        if let Some(previous) = self.precedence_namespaces.insert(step, namespace) {
            assert_eq!(
                previous, namespace,
                "precedence step has conflicting effective namespaces: {step:?}"
            );
        }
        step
    }

    pub(crate) fn node(&mut self, identity: ResolutionNodeIdentity) -> BindingNodeId {
        let mounted = identity.mount(self.fragment);
        register_identity(
            &mut self.nodes,
            &mut self.nodes_by_identity,
            mounted,
            identity,
            "node",
        );
        mounted
    }

    pub(crate) fn path(&mut self, identity: ResolutionPathIdentity) -> PartialPathId {
        let mounted = identity.mount(self.fragment);
        register_identity(
            &mut self.paths,
            &mut self.paths_by_identity,
            mounted,
            identity,
            "path",
        );
        mounted
    }

    pub(crate) fn stack_variable(
        &mut self,
        identity: ResolutionStackVariableIdentity,
    ) -> StackVariableId {
        let mounted = identity.mount(self.fragment);
        register_identity(
            &mut self.stack_variables,
            &mut self.stack_variables_by_identity,
            mounted,
            identity,
            "stack variable",
        );
        mounted
    }

    pub(crate) fn semantic_identity(
        &self,
        semantic: SemanticId,
    ) -> Option<ResolutionSemanticIdentity> {
        self.semantics.get(&semantic).copied()
    }

    pub(crate) fn path_identity(&self, path: PartialPathId) -> Option<ResolutionPathIdentity> {
        self.paths.get(&path).copied()
    }

    pub(crate) fn node_identity(&self, node: BindingNodeId) -> Option<ResolutionNodeIdentity> {
        self.nodes.get(&node).copied()
    }

    pub(crate) fn finish(self) -> ResolutionIdentityCatalog {
        for (&semantic, recipe) in &self.lookup_recipes {
            let identity = self
                .semantics
                .get(&semantic)
                .copied()
                .expect("lookup recipe semantic must be registered in the identity catalog");
            assert_eq!(
                identity.space(),
                ResolutionSemanticIdentitySpace::Shared,
                "lookup recipe semantic must use the Shared identity space: {recipe:?}"
            );
            assert_eq!(
                identity,
                recipe.identity(),
                "lookup recipe does not derive its registered semantic identity: {recipe:?}"
            );
        }
        for step in self.precedence_namespaces.keys() {
            assert!(
                self.semantics.contains_key(&step.semantic),
                "precedence step semantic must be registered in the identity catalog: {step:?}"
            );
        }
        ResolutionIdentityCatalog {
            fragment: self.fragment,
            semantics: canonical_entries(self.semantics),
            lookup_recipes: canonical_recipe_entries(self.lookup_recipes),
            precedence_namespaces: self.precedence_namespaces,
            nodes: canonical_entries(self.nodes),
            paths: canonical_entries(self.paths),
            stack_variables: canonical_entries(self.stack_variables),
        }
    }
}

fn register_lookup_recipe(
    by_semantic: &mut HashMap<SemanticId, ResolutionLookupSemanticRecipe>,
    by_recipe: &mut HashMap<ResolutionLookupSemanticRecipe, SemanticId>,
    semantic: SemanticId,
    recipe: ResolutionLookupSemanticRecipe,
) {
    if let Some(previous) = by_semantic.get(&semantic) {
        assert_eq!(
            previous, &recipe,
            "shared lookup semantic has conflicting canonical recipes: {semantic}"
        );
    }
    if let Some(previous) = by_recipe.get(&recipe) {
        assert_eq!(
            *previous, semantic,
            "canonical lookup recipe has conflicting shared semantics: {recipe:?}"
        );
    }
    by_semantic.insert(semantic, recipe.clone());
    by_recipe.insert(recipe, semantic);
}

fn register_identity<Mounted, Identity>(
    by_mounted: &mut HashMap<Mounted, Identity>,
    by_identity: &mut HashMap<Identity, Mounted>,
    mounted: Mounted,
    identity: Identity,
    label: &str,
) where
    Mounted: Copy + std::fmt::Debug + Eq + std::hash::Hash,
    Identity: Copy + std::fmt::Debug + Eq + std::hash::Hash,
{
    if let Some(previous) = by_mounted.insert(mounted, identity) {
        assert_eq!(
            previous, identity,
            "mounted resolution {label} has conflicting local identities: {mounted:?}"
        );
    }
    if let Some(previous) = by_identity.insert(identity, mounted) {
        assert_eq!(
            previous, mounted,
            "resolution {label} local identity has conflicting mounted values: {identity:?}"
        );
    }
}

fn canonical_entries<Mounted, Identity>(
    entries: HashMap<Mounted, Identity>,
) -> Vec<(Mounted, Identity)>
where
    Mounted: Copy + Ord,
    Identity: Copy + Ord,
{
    let mut entries = entries.into_iter().collect::<Vec<_>>();
    entries.sort_unstable_by_key(|(mounted, identity)| (*identity, *mounted));
    entries
}

fn canonical_recipe_entries(
    entries: HashMap<SemanticId, ResolutionLookupSemanticRecipe>,
) -> Vec<(SemanticId, ResolutionLookupSemanticRecipe)> {
    let mut entries = entries.into_iter().collect::<Vec<_>>();
    entries.sort_unstable_by(|(semantic_a, recipe_a), (semantic_b, recipe_b)| {
        (recipe_a, semantic_a).cmp(&(recipe_b, semantic_b))
    });
    entries
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolutionIdentityCatalog {
    fragment: BindingFragmentId,
    semantics: Vec<(SemanticId, ResolutionSemanticIdentity)>,
    lookup_recipes: Vec<(SemanticId, ResolutionLookupSemanticRecipe)>,
    precedence_namespaces: HashMap<PrecedenceStep, ResolutionNamespace>,
    nodes: Vec<(BindingNodeId, ResolutionNodeIdentity)>,
    paths: Vec<(PartialPathId, ResolutionPathIdentity)>,
    stack_variables: Vec<(StackVariableId, ResolutionStackVariableIdentity)>,
}

impl ResolutionIdentityCatalog {
    pub(crate) const fn fragment(&self) -> BindingFragmentId {
        self.fragment
    }

    pub(crate) fn semantic_identity(
        &self,
        semantic: SemanticId,
    ) -> Option<ResolutionSemanticIdentity> {
        lookup_identity(&self.semantics, semantic)
    }

    pub(crate) fn lookup_recipe(
        &self,
        semantic: SemanticId,
    ) -> Option<&ResolutionLookupSemanticRecipe> {
        self.lookup_recipes
            .iter()
            .find_map(|(candidate, recipe)| (*candidate == semantic).then_some(recipe))
    }

    pub(crate) fn precedence_namespace(&self, step: PrecedenceStep) -> Option<ResolutionNamespace> {
        self.precedence_namespaces.get(&step).copied()
    }

    pub(crate) const fn precedence_namespaces(
        &self,
    ) -> &HashMap<PrecedenceStep, ResolutionNamespace> {
        &self.precedence_namespaces
    }

    pub(crate) fn semantics(&self) -> &[(SemanticId, ResolutionSemanticIdentity)] {
        &self.semantics
    }

    pub(crate) fn lookup_recipes(&self) -> &[(SemanticId, ResolutionLookupSemanticRecipe)] {
        &self.lookup_recipes
    }

    pub(crate) fn nodes(&self) -> &[(BindingNodeId, ResolutionNodeIdentity)] {
        &self.nodes
    }

    pub(crate) fn paths(&self) -> &[(PartialPathId, ResolutionPathIdentity)] {
        &self.paths
    }

    pub(crate) fn stack_variables(&self) -> &[(StackVariableId, ResolutionStackVariableIdentity)] {
        &self.stack_variables
    }
}

fn lookup_identity<Mounted, Identity>(
    entries: &[(Mounted, Identity)],
    mounted: Mounted,
) -> Option<Identity>
where
    Mounted: Copy + Eq,
    Identity: Copy,
{
    entries
        .iter()
        .find_map(|&(candidate, identity)| (candidate == mounted).then_some(identity))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fragment(label: &[u8]) -> BindingFragmentId {
        BindingFragmentId::hash_bytes(label)
    }

    #[test]
    fn canonical_catalog_order_depends_on_local_recipes_not_mounts() {
        let first = ResolutionSemanticIdentity::fragment_local([1; 32]);
        let second = ResolutionSemanticIdentity::fragment_local([2; 32]);
        let shared = ResolutionSemanticIdentity::shared([3; 32]);
        let fragments = [fragment(b"catalog-a"), fragment(b"catalog-b")];
        let catalogs = fragments.map(|fragment| {
            let mut builder = ResolutionIdentityCatalogBuilder::new(fragment);
            builder.semantic(second);
            builder.semantic(shared);
            builder.semantic(first);
            builder.semantic(first);
            builder.finish()
        });

        let recipes = catalogs.each_ref().map(|catalog| {
            catalog
                .semantics()
                .iter()
                .map(|&(_, identity)| identity)
                .collect::<Vec<_>>()
        });
        assert_eq!(recipes[0], vec![first, second, shared]);
        assert_eq!(recipes[0], recipes[1]);
        assert_ne!(first.mount(fragments[0]), first.mount(fragments[1]));
        assert_eq!(shared.mount(fragments[0]), shared.mount(fragments[1]));
        for (fragment, catalog) in fragments.into_iter().zip(catalogs) {
            for &(_, identity) in catalog.semantics() {
                assert_eq!(
                    catalog.semantic_identity(identity.mount(fragment)),
                    Some(identity)
                );
            }
        }
    }

    #[test]
    fn lookup_recipe_fields_are_separate_and_canonically_ordered() {
        let recipes = [
            (Language::Java, ResolutionNamespace::Type, "Name"),
            (Language::Go, ResolutionNamespace::Type, "Name"),
            (Language::Java, ResolutionNamespace::Value, "Name"),
            (Language::Java, ResolutionNamespace::Type, "Other"),
        ];
        let mut builder = ResolutionIdentityCatalogBuilder::new(fragment(b"lookup-recipes"));
        let semantics = recipes.map(|(language, namespace, spelling)| {
            builder.lookup_semantic(language, namespace, spelling)
        });
        builder.lookup_semantic(Language::Java, ResolutionNamespace::Type, "Name");
        let catalog = builder.finish();

        assert_eq!(
            semantics
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            4
        );
        assert_eq!(catalog.lookup_recipes().len(), 4);
        assert!(catalog.lookup_recipes().windows(2).all(|pair| {
            let (semantic_a, recipe_a) = &pair[0];
            let (semantic_b, recipe_b) = &pair[1];
            (recipe_a, semantic_a) < (recipe_b, semantic_b)
        }));
        for &(semantic, ref recipe) in catalog.lookup_recipes() {
            assert_eq!(
                SemanticId::from_digest(recipe.identity().digest()),
                semantic
            );
            assert_eq!(catalog.lookup_recipe(semantic), Some(recipe));
            assert_eq!(catalog.semantic_identity(semantic), Some(recipe.identity()));
        }
    }

    #[test]
    fn lookup_recipes_are_permutation_stable_and_mount_independent() {
        let recipes = [
            (Language::Java, ResolutionNamespace::Callable, "run"),
            (Language::Java, ResolutionNamespace::Type, "Widget"),
            (Language::Java, ResolutionNamespace::Value, "field"),
        ];
        let fragments = [fragment(b"lookup-mount-a"), fragment(b"lookup-mount-b")];
        let mut first = ResolutionIdentityCatalogBuilder::new(fragments[0]);
        for (language, namespace, spelling) in recipes {
            first.lookup_semantic(language, namespace, spelling);
        }
        let mut second = ResolutionIdentityCatalogBuilder::new(fragments[1]);
        for (language, namespace, spelling) in recipes.into_iter().rev() {
            second.lookup_semantic(language, namespace, spelling);
        }
        let catalogs = [first.finish(), second.finish()];

        assert_eq!(catalogs[0].lookup_recipes(), catalogs[1].lookup_recipes());
        for &(semantic, ref recipe) in catalogs[0].lookup_recipes() {
            assert_eq!(recipe.semantic_language(), "java");
            assert_eq!(
                SemanticId::from_digest(recipe.identity().digest()),
                semantic
            );
            assert_eq!(recipe.identity().mount(fragments[0]), semantic);
            assert_eq!(recipe.identity().mount(fragments[1]), semantic);
        }
    }

    #[test]
    #[should_panic(expected = "does not derive its registered semantic identity")]
    fn catalog_completion_rejects_forged_lookup_recipe_identity() {
        let mut builder = ResolutionIdentityCatalogBuilder::new(fragment(b"forged-recipe"));
        let semantic = builder.semantic(ResolutionSemanticIdentity::shared([10; 32]));
        register_lookup_recipe(
            &mut builder.lookup_recipes,
            &mut builder.lookup_semantics_by_recipe,
            semantic,
            ResolutionLookupSemanticRecipe::new(Language::Java, ResolutionNamespace::Type, "Name"),
        );
        builder.finish();
    }
    #[test]
    #[should_panic(expected = "conflicting local identities")]
    fn conflicting_mounted_identity_fails_closed() {
        let mut forward = HashMap::default();
        let mut reverse = HashMap::default();
        register_identity(&mut forward, &mut reverse, 1_u8, 2_u8, "test");
        register_identity(&mut forward, &mut reverse, 1_u8, 3_u8, "test");
    }

    #[test]
    #[should_panic(expected = "conflicting mounted values")]
    fn conflicting_recipe_identity_fails_closed() {
        let mut forward = HashMap::default();
        let mut reverse = HashMap::default();
        register_identity(&mut forward, &mut reverse, 1_u8, 2_u8, "test");
        register_identity(&mut forward, &mut reverse, 3_u8, 2_u8, "test");
    }

    #[test]
    #[should_panic(expected = "conflicting canonical recipes")]
    fn same_lookup_digest_with_different_recipe_fails_closed() {
        let mut by_semantic = HashMap::default();
        let mut by_recipe = HashMap::default();
        let semantic = SemanticId::from_digest([7; 32]);
        register_lookup_recipe(
            &mut by_semantic,
            &mut by_recipe,
            semantic,
            ResolutionLookupSemanticRecipe::new(Language::Java, ResolutionNamespace::Type, "Name"),
        );
        register_lookup_recipe(
            &mut by_semantic,
            &mut by_recipe,
            semantic,
            ResolutionLookupSemanticRecipe::new(Language::Java, ResolutionNamespace::Value, "Name"),
        );
    }

    #[test]
    #[should_panic(expected = "conflicting shared semantics")]
    fn same_lookup_recipe_with_different_digest_fails_closed() {
        let mut by_semantic = HashMap::default();
        let mut by_recipe = HashMap::default();
        let recipe =
            ResolutionLookupSemanticRecipe::new(Language::Java, ResolutionNamespace::Type, "Name");
        register_lookup_recipe(
            &mut by_semantic,
            &mut by_recipe,
            SemanticId::from_digest([8; 32]),
            recipe.clone(),
        );
        register_lookup_recipe(
            &mut by_semantic,
            &mut by_recipe,
            SemanticId::from_digest([9; 32]),
            recipe,
        );
    }
    #[test]
    fn every_local_identity_kind_rebases_from_its_recipe() {
        let fragment_a = fragment(b"local-identity-a");
        let fragment_b = fragment(b"local-identity-b");
        let node = ResolutionNodeIdentity::new([4; 32]);
        let path = ResolutionPathIdentity::new([5; 32]);
        let variable = ResolutionStackVariableIdentity::new([6; 32]);
        let mut builder = ResolutionIdentityCatalogBuilder::new(fragment_a);
        let mounted_node = builder.node(node);
        let mounted_path = builder.path(path);
        let mounted_variable = builder.stack_variable(variable);
        let catalog = builder.finish();

        assert_eq!(
            catalog
                .nodes()
                .iter()
                .find_map(|(id, identity)| (*id == mounted_node).then_some(*identity)),
            Some(node)
        );
        assert_eq!(
            catalog
                .paths()
                .iter()
                .find_map(|(id, identity)| (*id == mounted_path).then_some(*identity)),
            Some(path)
        );
        assert_eq!(
            catalog
                .stack_variables()
                .iter()
                .find_map(|(id, identity)| (*id == mounted_variable).then_some(*identity)),
            Some(variable)
        );
        assert_eq!(
            node.mount(fragment_b),
            BindingNodeId::in_fragment(fragment_b, &node.digest())
        );
        assert_eq!(
            path.mount(fragment_b),
            PartialPathId::in_fragment(fragment_b, &path.digest())
        );
        assert_eq!(
            variable.mount(fragment_b),
            StackVariableId::in_fragment(fragment_b, &variable.digest())
        );
    }
}
