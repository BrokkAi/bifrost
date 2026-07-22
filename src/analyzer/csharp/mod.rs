mod adapter;
mod cache;
mod clones;
mod declarations;
mod dependency_discovery;
pub mod external;
mod hierarchy;
mod imports;
mod semantic;
pub(crate) mod structural;
mod tests;

use crate::analyzer::clone_detection::{CloneCandidateProfile, detect_structural_clone_smells};
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CSharpAnalyzerConfig, CallableArity,
    CodeUnit, IAnalyzer, ImportAnalysisProvider, Language, Project, ProjectFile, SignatureMetadata,
    TestAssertionSmell, TestAssertionWeights, TestDetectionProvider, TreeSitterAnalyzer,
    TypeHierarchyProvider, UsageFactsIndex,
};
use crate::hash::{HashMap, HashSet};
use crate::{CloneSmell, CloneSmellWeights};
use std::collections::BTreeSet;
use std::sync::Arc;
use tree_sitter::Node;

use adapter::CSharpAdapter;
use cache::CSharpMemoCaches;
use clones::{build_csharp_clone_candidate_data, refine_csharp_clone_similarity};
use external::{CSharpExternalDeclarationIndex, CSharpExternalMember, CSharpExternalType};
use imports::{
    csharp_static_using_from_import, csharp_using_alias_from_import, csharp_using_namespace,
};
use tests::detect_csharp_test_assertion_smells;

pub(crate) fn csharp_using_directive_is_static(node: Node<'_>) -> bool {
    if node.kind() != "using_directive" {
        return false;
    }
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| child.kind() == "static")
}

pub(crate) use dependency_discovery::is_csharp_dependency_input;

pub(crate) fn csharp_using_directive_is_global(node: Node<'_>) -> bool {
    if node.kind() != "using_directive" {
        return false;
    }
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| child.kind() == "global")
}

pub(crate) fn csharp_using_directive_target(node: Node<'_>, source: &str) -> Option<String> {
    csharp_using_directive_target_node(node)
        .map(|target| csharp_type_node_identity(target, source))
        .filter(|target| !target.is_empty())
}

pub(crate) fn csharp_using_directive_target_node(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "using_directive" {
        return None;
    }
    let alias = node.child_by_field_name("name");
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| alias.is_none_or(|alias| child != &alias))
}

pub(crate) fn csharp_using_directive_namespace(node: Node<'_>, source: &str) -> Option<String> {
    (!csharp_using_directive_is_static(node) && node.child_by_field_name("name").is_none())
        .then(|| csharp_using_directive_target(node, source))
        .flatten()
}

pub(crate) fn csharp_as_expression_type_operand(parent: Node<'_>, node: Node<'_>) -> bool {
    parent.kind() == "as_expression"
        && parent.child_by_field_name("right").is_some_and(|right| {
            right.start_byte() == node.start_byte() && right.end_byte() == node.end_byte()
        })
}

pub(crate) fn csharp_is_expression_type_operand(parent: Node<'_>, node: Node<'_>) -> bool {
    parent.kind() == "is_expression"
        && parent.child_by_field_name("right").is_some_and(|right| {
            right.start_byte() == node.start_byte() && right.end_byte() == node.end_byte()
        })
}

#[derive(Clone)]
pub struct CSharpAnalyzer {
    inner: TreeSitterAnalyzer<CSharpAdapter>,
    memo_caches: Arc<CSharpMemoCaches>,
    csharp_config: CSharpAnalyzerConfig,
    external_index: Arc<std::sync::OnceLock<CSharpExternalDeclarationIndex>>,
}

crate::analyzer::impl_forward_query_provider!(CSharpAnalyzer);

impl CSharpAnalyzer {
    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone.external_index = Arc::new(std::sync::OnceLock::new());
        clone
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let csharp_config = config.csharp.clone();
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, CSharpAdapter, config),
            memo_caches: Arc::new(CSharpMemoCaches::new(memo_budget)),
            csharp_config,
            external_index: Arc::new(std::sync::OnceLock::new()),
        }
    }

    pub(crate) fn new_with_config_store_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, crate::analyzer::store::StoreError> {
        let memo_budget = config.memo_cache_budget_bytes();
        let csharp_config = config.csharp.clone();
        let inner = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            CSharpAdapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self {
            inner,
            memo_caches: Arc::new(CSharpMemoCaches::new(memo_budget)),
            csharp_config,
            external_index: Arc::new(std::sync::OnceLock::new()),
        })
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    #[doc(hidden)]
    pub fn reset_full_declaration_scan_count_for_test(&self) {
        self.inner.reset_full_declaration_scan_count_for_test();
    }

    #[doc(hidden)]
    pub fn full_declaration_scan_count_for_test(&self) -> usize {
        self.inner.full_declaration_scan_count_for_test()
    }

    #[doc(hidden)]
    pub fn reset_full_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    #[doc(hidden)]
    pub fn full_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test()
    }

    #[doc(hidden)]
    pub fn reset_definition_candidates_query_count_for_test(&self) {
        self.inner
            .reset_definition_candidates_query_count_for_test();
    }

    #[doc(hidden)]
    pub fn definition_candidates_query_count_for_test(&self) -> usize {
        self.inner.definition_candidates_query_count_for_test()
    }

    pub(crate) fn declaration_candidates_by_identifier(
        &self,
        identifier: &str,
    ) -> BTreeSet<CodeUnit> {
        self.inner.lookup_declarations_by_identifier(identifier)
    }

    pub(crate) fn usage_declaration_candidates_by_identifier(
        &self,
        identifier: &str,
    ) -> &[CodeUnit] {
        self.inner
            .global_usage_definition_index()
            .identifier(identifier)
    }

    pub(crate) fn declaration_candidates_by_fqn(
        &self,
        fqn: &str,
        normalized: bool,
    ) -> BTreeSet<CodeUnit> {
        self.inner
            .lookup_declarations_by_persisted_fqn(fqn, normalized)
    }

    pub(crate) fn member_candidates_for_owner(
        &self,
        owner_fqn: &str,
        name: &str,
    ) -> BTreeSet<CodeUnit> {
        self.inner.lookup_members_for_owner_name(owner_fqn, name)
    }

    pub(crate) fn usage_member_candidates_for_owner(
        &self,
        owner_fqn: &str,
        name: &str,
    ) -> Vec<CodeUnit> {
        let normalized = csharp_normalize_full_name(owner_fqn);
        self.inner
            .global_usage_definition_index()
            .members_for_owner_name(owner_fqn, &normalized, name)
            .into_iter()
            .cloned()
            .collect()
    }

    pub(crate) fn workspace_namespace_exists(&self, namespace: &str) -> bool {
        self.inner.persisted_package_exists(namespace)
    }

    pub(crate) fn usage_workspace_namespace_exists(&self, namespace: &str) -> bool {
        self.inner
            .global_usage_definition_index()
            .package_exists(namespace)
    }

    pub fn namespace_of_file(&self, file: &ProjectFile) -> String {
        if let Some(cached) = self.memo_caches.namespace_by_file.get(file) {
            return (*cached).clone();
        }
        let package = self.inner.package_name_of(file).unwrap_or_default();
        let namespace = if package.is_empty() {
            self.declarations(file)
                .into_iter()
                .map(|unit| unit.package_name().to_string())
                .find(|package| !package.is_empty())
                .unwrap_or_default()
        } else {
            package
        };
        self.memo_caches
            .namespace_by_file
            .insert(file.clone(), Arc::new(namespace.clone()));
        namespace
    }

    pub fn external_declaration_index(&self) -> &CSharpExternalDeclarationIndex {
        self.external_index.get_or_init(|| {
            CSharpExternalDeclarationIndex::build_for_project(
                &self.csharp_config,
                self.inner.project(),
            )
        })
    }

    pub fn external_type_candidates(
        &self,
        file: &ProjectFile,
        reference: &str,
    ) -> Vec<&CSharpExternalType> {
        self.external_declaration_index().resolve_in_file(
            reference,
            &self.namespace_of_file(file),
            &self.using_namespaces_of(file),
            &self.using_aliases_of(file),
        )
    }

    pub fn external_member_candidates(
        &self,
        owner: &str,
        name: &str,
    ) -> Vec<&CSharpExternalMember> {
        self.external_declaration_index().members_named(owner, name)
    }

    pub fn using_namespaces_of(&self, file: &ProjectFile) -> Vec<String> {
        if let Some(cached) = self.memo_caches.using_namespaces.get(file) {
            return (*cached).clone();
        }

        let mut namespaces: Vec<String> = self
            .inner
            .import_info_of(file)
            .iter()
            .filter_map(|import| csharp_using_namespace(&import.raw_snippet))
            .collect();
        for namespace in self.global_using_namespaces() {
            if !namespaces.contains(namespace) {
                namespaces.push(namespace.clone());
            }
        }
        self.memo_caches
            .using_namespaces
            .insert(file.clone(), Arc::new(namespaces.clone()));
        namespaces
    }

    pub fn using_aliases_of(&self, file: &ProjectFile) -> HashMap<String, String> {
        if let Some(cached) = self.memo_caches.using_aliases.get(file) {
            return (*cached).clone();
        }

        let mut aliases: HashMap<String, String> = self
            .inner
            .import_info_of(file)
            .iter()
            .filter_map(csharp_using_alias_from_import)
            .collect();
        for (alias, target) in self.global_using_aliases() {
            aliases
                .entry(alias.clone())
                .or_insert_with(|| target.clone());
        }
        self.memo_caches
            .using_aliases
            .insert(file.clone(), Arc::new(aliases.clone()));
        aliases
    }

    pub(crate) fn global_using_namespaces(&self) -> &HashSet<String> {
        self.memo_caches.global_using_namespaces.get_or_init(|| {
            self.inner
                .all_files()
                .into_iter()
                .flat_map(|file| self.inner.import_info_of(&file).into_iter())
                .filter(|import| import.raw_snippet.trim_start().starts_with("global using "))
                .filter_map(|import| csharp_using_namespace(&import.raw_snippet))
                .map(|namespace| {
                    normalize_csharp_type_fragment(
                        namespace.strip_prefix("global::").unwrap_or(&namespace),
                    )
                })
                .filter(|namespace| !namespace.is_empty())
                .collect()
        })
    }

    fn global_using_aliases(&self) -> &HashMap<String, String> {
        self.memo_caches.global_using_aliases.get_or_init(|| {
            self.inner
                .all_files()
                .into_iter()
                .flat_map(|file| self.inner.import_info_of(&file).into_iter())
                .filter(|import| import.raw_snippet.trim_start().starts_with("global using "))
                .filter_map(|import| csharp_using_alias_from_import(&import))
                .collect()
        })
    }

    pub(crate) fn global_static_using_types(&self) -> &[CodeUnit] {
        self.memo_caches.global_static_using_types.get_or_init(|| {
            let mut types = Vec::new();
            for file in self.inner.all_files() {
                for target in self
                    .inner
                    .import_info_of(&file)
                    .iter()
                    .filter(|import| import.raw_snippet.trim_start().starts_with("global using "))
                    .filter_map(csharp_static_using_from_import)
                {
                    let target = normalize_csharp_type_fragment(
                        target.strip_prefix("global::").unwrap_or(target),
                    );
                    types.extend(self.type_candidates_by_fqn(&target, false));
                }
            }
            types.sort();
            types.dedup();
            types
        })
    }

    pub(crate) fn usage_global_static_using_types(&self) -> &[CodeUnit] {
        self.memo_caches
            .usage_global_static_using_types
            .get_or_init(|| {
                let mut types = Vec::new();
                for file in self.inner.all_files() {
                    for target in self
                        .inner
                        .import_info_of(&file)
                        .iter()
                        .filter(|import| {
                            import.raw_snippet.trim_start().starts_with("global using ")
                        })
                        .filter_map(csharp_static_using_from_import)
                    {
                        let target = normalize_csharp_type_fragment(
                            target.strip_prefix("global::").unwrap_or(target),
                        );
                        types.extend(self.type_candidates_by_fqn(&target, true));
                    }
                }
                types.sort();
                types.dedup();
                types
            })
    }

    pub fn visible_type_candidates(&self, file: &ProjectFile, name: &str) -> Vec<CodeUnit> {
        self.visible_type_candidates_inner(file, name, true, false)
    }

    pub(crate) fn usage_visible_type_candidates(
        &self,
        file: &ProjectFile,
        name: &str,
    ) -> Vec<CodeUnit> {
        self.visible_type_candidates_inner(file, name, true, true)
    }

    pub(crate) fn partial_type_parts(&self, owner: &CodeUnit) -> Vec<CodeUnit> {
        if !owner.is_class() {
            return Vec::new();
        }
        let owner_key = self.type_declaration_key(owner);
        let mut parts: Vec<_> = self
            .inner
            .get_definitions(&owner.fq_name())
            .into_iter()
            .filter(|unit| unit.is_class() && self.type_declaration_key(unit) == owner_key)
            .collect();
        self.sort_type_candidates(&mut parts);
        parts.dedup();
        parts
    }

    pub(crate) fn usage_partial_type_parts(&self, owner: &CodeUnit) -> Vec<CodeUnit> {
        if !owner.is_class() {
            return Vec::new();
        }
        let owner_key = self.type_declaration_key(owner);
        let mut parts: Vec<_> = self
            .usage_definition_candidates_by_fqn(&owner.fq_name())
            .into_iter()
            .filter(|unit| unit.is_class() && self.type_declaration_key(unit) == owner_key)
            .collect();
        self.sort_type_candidates(&mut parts);
        parts.dedup();
        parts
    }

    pub(crate) fn sort_dedup_type_candidates(&self, candidates: &mut Vec<CodeUnit>) {
        let mut keyed: Vec<_> = candidates
            .drain(..)
            .map(|unit| {
                let key = self.type_declaration_key(&unit);
                let source = crate::path_utils::rel_path_string(unit.source());
                (unit, key, source)
            })
            .collect();
        keyed.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.2.cmp(&right.2)));
        keyed.dedup_by(|left, right| left.1 == right.1);
        candidates.extend(keyed.into_iter().map(|(unit, _, _)| unit));
    }

    pub(crate) fn sort_type_candidates(&self, candidates: &mut [CodeUnit]) {
        candidates.sort_by_cached_key(|unit| {
            (
                self.type_declaration_key(unit),
                crate::path_utils::rel_path_string(unit.source()),
            )
        });
    }

    pub(crate) fn logical_type_count(&self, candidates: &[CodeUnit]) -> usize {
        candidates
            .iter()
            .map(|unit| self.type_declaration_key(unit))
            .collect::<HashSet<_>>()
            .len()
    }

    pub(crate) fn first_logical_type_fqn(&self, candidates: &[CodeUnit]) -> Option<String> {
        let mut sorted = candidates.to_vec();
        self.sort_type_candidates(&mut sorted);
        sorted.first().map(CodeUnit::fq_name)
    }

    fn type_declaration_key(&self, unit: &CodeUnit) -> String {
        unit.fq_name()
    }

    pub fn resolve_visible_type(&self, file: &ProjectFile, name: &str) -> Option<CodeUnit> {
        let candidates = self.visible_type_candidates(file, name);
        (self.logical_type_count(&candidates) == 1)
            .then(|| {
                let mut candidates = candidates;
                self.sort_type_candidates(&mut candidates);
                candidates.into_iter().next()
            })
            .flatten()
    }

    pub(crate) fn resolve_usage_visible_type(
        &self,
        file: &ProjectFile,
        name: &str,
    ) -> Option<CodeUnit> {
        let candidates = self.usage_visible_type_candidates(file, name);
        (self.logical_type_count(&candidates) == 1)
            .then(|| {
                let mut candidates = candidates;
                self.sort_type_candidates(&mut candidates);
                candidates.into_iter().next()
            })
            .flatten()
    }

    fn visible_type_candidates_inner(
        &self,
        file: &ProjectFile,
        name: &str,
        resolve_aliases: bool,
        usage: bool,
    ) -> Vec<CodeUnit> {
        let mut normalized = normalize_csharp_type_fragment(name);
        if normalized.is_empty() {
            return Vec::new();
        }
        let mut global_qualified = false;
        if let Some((alias, suffix)) = normalized.split_once("::") {
            normalized = if alias == "global" {
                global_qualified = true;
                suffix.to_string()
            } else if let Some(target) = self.using_aliases_of(file).get(alias) {
                if suffix.is_empty() {
                    target.clone()
                } else {
                    format!("{target}.{suffix}")
                }
            } else {
                return Vec::new();
            };
        }
        if global_qualified {
            return self.type_candidates_by_fqn(&normalized, usage);
        }
        if resolve_aliases
            && let Some(target) = self.using_aliases_of(file).get(&normalized)
            && target != &normalized
        {
            return self.visible_type_candidates_inner(file, target, false, usage);
        }

        let mut namespace = self.namespace_of_file(file);
        if !namespace.is_empty() {
            let candidates =
                self.type_candidates_by_fqn(&format!("{namespace}.{normalized}"), usage);
            if !candidates.is_empty() {
                return candidates;
            }
        }

        let mut visible = Vec::new();
        for using_namespace in self.using_namespaces_of(file) {
            visible.extend(
                self.type_candidates_by_fqn(&format!("{using_namespace}.{normalized}"), usage)
                    .into_iter()
                    .filter(|candidate| candidate.package_name() == using_namespace),
            );
        }
        if !visible.is_empty() {
            return visible;
        }

        while let Some(separator) = namespace.rfind('.') {
            namespace.truncate(separator);
            let candidates =
                self.type_candidates_by_fqn(&format!("{namespace}.{normalized}"), usage);
            if !candidates.is_empty() {
                return candidates;
            }
        }

        self.type_candidates_by_fqn(&normalized, usage)
    }

    fn type_candidates_by_fqn(&self, fqn: &str, usage: bool) -> Vec<CodeUnit> {
        if usage {
            return self.usage_type_candidates_by_fqn(fqn);
        }
        self.inner
            .forward_definition_fqn(fqn)
            .into_iter()
            .filter(|unit| unit.is_class())
            .collect()
    }

    pub(crate) fn usage_type_candidates_by_fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        let index = self.inner.global_usage_definition_index();
        let exact = index
            .by_fqn(fqn)
            .iter()
            .filter(|unit| unit.is_class())
            .cloned()
            .collect::<Vec<_>>();
        if !exact.is_empty() {
            return exact;
        }
        let arity_key = csharp_arity_preserving_full_name(fqn);
        index
            .by_normalized_fqn(&csharp_normalize_full_name(fqn))
            .iter()
            .filter(|unit| {
                unit.is_class() && csharp_arity_preserving_full_name(&unit.fq_name()) == arity_key
            })
            .cloned()
            .collect()
    }

    pub(crate) fn usage_definition_candidates_by_fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        let index = self.inner.global_usage_definition_index();
        let exact = index.by_fqn(fqn);
        if !exact.is_empty() {
            return exact.to_vec();
        }
        let arity_key = csharp_arity_preserving_full_name(fqn);
        index
            .by_normalized_fqn(&csharp_normalize_full_name(fqn))
            .iter()
            .filter(|unit| csharp_arity_preserving_full_name(&unit.fq_name()) == arity_key)
            .cloned()
            .collect()
    }
}

fn csharp_arity_preserving_full_name(fq_name: &str) -> String {
    let normalized = fq_name
        .strip_prefix("global::")
        .unwrap_or(fq_name)
        .replace(['$', '+'], ".");
    normalize_csharp_constructor_name(normalized)
}

pub(crate) fn csharp_normalize_full_name(fq_name: &str) -> String {
    let normalized = fq_name
        .strip_prefix("global::")
        .unwrap_or(fq_name)
        .replace(['$', '+'], ".")
        .split('.')
        .map(strip_csharp_generic_arity)
        .collect::<Vec<_>>()
        .join(".");
    normalize_csharp_constructor_name(normalized)
}

fn normalize_csharp_constructor_name(normalized: String) -> String {
    let Some(owner) = normalized.strip_suffix(".#ctor") else {
        return normalized;
    };
    if owner.is_empty() {
        return normalized;
    }

    let constructor_name = owner
        .rfind('.')
        .map(|separator| &owner[separator + 1..])
        .unwrap_or(owner);
    let constructor_name = strip_csharp_generic_arity(constructor_name);
    if constructor_name.is_empty() {
        normalized
    } else {
        format!("{owner}.{constructor_name}")
    }
}

pub(crate) fn strip_csharp_generic_arity(segment: &str) -> &str {
    let Some((name, arity)) = segment.rsplit_once('`') else {
        return segment;
    };
    let backticks = 1 + name.bytes().rev().take_while(|byte| *byte == b'`').count();
    let name = name.trim_end_matches('`');
    if !name.is_empty()
        && (1..=2).contains(&backticks)
        && !arity.is_empty()
        && arity.bytes().all(|byte| byte.is_ascii_digit())
    {
        name
    } else {
        segment
    }
}

pub(crate) fn csharp_source_identifier(unit: &CodeUnit) -> &str {
    strip_csharp_generic_arity(unit.identifier())
}

pub(crate) fn csharp_source_name_segment(segment: &str) -> &str {
    strip_csharp_generic_arity(segment)
}

pub(crate) fn csharp_type_node_identity(node: Node<'_>, source: &str) -> String {
    csharp_type_node_identity_with_terminal_suffix(node, source, "", false)
}

fn csharp_type_node_identity_with_terminal_suffix(
    node: Node<'_>,
    source: &str,
    terminal_suffix: &str,
    strip_terminal_verbatim_prefix: bool,
) -> String {
    let mut segments = Vec::new();
    let mut stack = vec![node];
    let mut alias_qualified = false;
    while let Some(current) = stack.pop() {
        match current.kind() {
            "qualified_name" | "alias_qualified_name" | "member_access_expression" => {
                alias_qualified |= current.kind() == "alias_qualified_name";
                let qualifier = current
                    .child_by_field_name("qualifier")
                    .or_else(|| current.child_by_field_name("alias"))
                    .or_else(|| current.child_by_field_name("expression"))
                    .or_else(|| current.named_child(0));
                let name = current
                    .child_by_field_name("name")
                    .or_else(|| current.named_child(current.named_child_count().saturating_sub(1)));
                if let Some(name) = name {
                    stack.push(name);
                }
                if let Some(qualifier) = qualifier {
                    stack.push(qualifier);
                }
            }
            "generic_name" => {
                let name = current
                    .child_by_field_name("name")
                    .or_else(|| current.named_child(0));
                let type_arguments = (0..current.named_child_count())
                    .filter_map(|index| current.named_child(index))
                    .find(|child| child.kind() == "type_argument_list");
                if let Some(name) = name {
                    let source_name = source
                        .get(name.start_byte()..name.end_byte())
                        .unwrap_or("")
                        .trim();
                    let arity = type_arguments.map_or(0, |arguments| arguments.named_child_count());
                    if !source_name.is_empty() {
                        segments.push(if arity == 0 {
                            source_name.to_string()
                        } else {
                            format!("{source_name}`{arity}")
                        });
                    }
                }
            }
            "nullable_type"
            | "array_type"
            | "pointer_type"
            | "type"
            | "simple_base_type"
            | "primary_constructor_base_type" => {
                if let Some(inner) = current
                    .child_by_field_name("type")
                    .or_else(|| current.named_child(0))
                {
                    stack.push(inner);
                }
            }
            "identifier" | "predefined_type" => {
                let segment = source
                    .get(current.start_byte()..current.end_byte())
                    .unwrap_or("")
                    .trim();
                if !segment.is_empty() {
                    segments.push(segment.to_string());
                }
            }
            _ => {
                let fallback = source
                    .get(current.start_byte()..current.end_byte())
                    .map(normalize_csharp_type_fragment)
                    .unwrap_or_default();
                if !fallback.is_empty() {
                    segments.push(fallback);
                }
            }
        }
    }
    if let Some(terminal) = segments.last_mut() {
        if strip_terminal_verbatim_prefix && terminal.starts_with('@') {
            terminal.remove(0);
        }
        terminal.push_str(terminal_suffix);
    }
    if alias_qualified && segments.len() > 1 {
        format!("{}::{}", segments[0], segments[1..].join("."))
    } else {
        segments.join(".")
    }
}

pub(crate) fn csharp_type_reference_root(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        let parent = node.parent()?;
        if matches!(
            parent.kind(),
            "qualified_name"
                | "alias_qualified_name"
                | "generic_name"
                | "nullable_type"
                | "array_type"
                | "pointer_type"
                | "type"
                | "simple_base_type"
                | "primary_constructor_base_type"
        ) {
            node = parent;
            continue;
        }
        if csharp_is_structured_type_role(parent, node)
            || csharp_as_expression_type_operand(parent, node)
            || csharp_is_expression_type_operand(parent, node)
        {
            return Some(node);
        }
        if matches!(
            parent.kind(),
            "type_argument_list" | "base_list" | "explicit_interface_specifier"
        ) || parent.kind() == "object_creation_expression"
        {
            return Some(node);
        }
        if parent.kind() == "using_directive"
            && (parent.child_by_field_name("name").is_some()
                || csharp_using_directive_is_static(parent))
            && csharp_using_directive_target_node(parent)
                .is_some_and(|target| same_csharp_node(target, node))
        {
            return Some(node);
        }
        if matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "struct_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "record_struct_declaration"
        ) && !parent
            .child_by_field_name("name")
            .is_some_and(|name| same_csharp_node(name, node))
        {
            return Some(node);
        }
        return None;
    }
}

fn csharp_is_structured_type_role(parent: Node<'_>, node: Node<'_>) -> bool {
    // A tuple element exposes both `type` and `name` identifier children. Keep
    // that distinction declaration-driven: only the grammar's `type` field is
    // a reference, even when the element name has identical text.
    let fields: &[&str] = if parent.kind() == "tuple_element" {
        &["type"]
    } else {
        &["type", "return_type", "returns"]
    };
    fields.iter().any(|field| {
        parent
            .child_by_field_name(field)
            .is_some_and(|candidate| same_csharp_node(candidate, node))
    })
}

/// Return the expression that can denote a type in a `nameof(...)` operand.
///
/// C# parses `nameof(Type)` in expression position, so the identifier does not
/// carry one of the ordinary syntax-tree type roles handled by
/// [`csharp_type_reference_root`]. A qualified operand may itself be a type
/// (`nameof(Namespace.Type)`); otherwise its receiver may be the type owner
/// (`nameof(Type.Member)`). Resolution remains responsible for choosing the
/// first valid interpretation and rejecting locals, fields, and other value
/// expressions with the same shape.
pub(crate) fn csharp_nameof_type_candidates<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, Option<Node<'tree>>)> {
    if node.kind() != "invocation_expression" {
        return None;
    }
    let function = node
        .child_by_field_name("function")
        .or_else(|| node.named_child(0))?;
    if function.kind() != "identifier"
        || source.get(function.start_byte()..function.end_byte())? != "nameof"
    {
        return None;
    }
    let arguments = node.child_by_field_name("arguments").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| child.kind() == "argument_list")
    })?;
    if arguments.named_child_count() != 1 {
        return None;
    }
    let argument = arguments.named_child(0)?;
    let operand = if argument.kind() == "argument" {
        argument
            .child_by_field_name("value")
            .or_else(|| argument.child_by_field_name("expression"))
            .or_else(|| argument.named_child(0))?
    } else {
        argument
    };
    let qualified_owner = if operand.kind() == "member_access_expression" {
        Some(
            operand
                .child_by_field_name("expression")
                .or_else(|| operand.named_child(0))?,
        )
    } else {
        None
    };
    matches!(
        operand.kind(),
        "identifier"
            | "qualified_name"
            | "alias_qualified_name"
            | "generic_name"
            | "member_access_expression"
    )
    .then_some((operand, qualified_owner))
}

pub(crate) fn csharp_constant_pattern_type_candidate(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "constant_pattern" {
        return None;
    }
    let mut candidate = node.named_child(0)?;
    while candidate.kind() == "binary_expression" {
        candidate = candidate
            .child_by_field_name("left")
            .or_else(|| candidate.named_child(0))?;
    }
    matches!(
        candidate.kind(),
        "identifier"
            | "qualified_name"
            | "alias_qualified_name"
            | "generic_name"
            | "member_access_expression"
    )
    .then_some(candidate)
}

pub(crate) fn csharp_member_access_type_receiver(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "member_access_expression" {
        return None;
    }
    let receiver = node
        .child_by_field_name("expression")
        .or_else(|| node.named_child(0))?;
    matches!(
        receiver.kind(),
        "identifier"
            | "qualified_name"
            | "alias_qualified_name"
            | "generic_name"
            | "member_access_expression"
    )
    .then_some(receiver)
}

pub(crate) fn csharp_type_terminal_identifier(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "identifier" | "predefined_type" => return Some(node),
            "qualified_name" | "alias_qualified_name" | "member_access_expression" => {
                node = node
                    .child_by_field_name("name")
                    .or_else(|| node.named_child(node.named_child_count().saturating_sub(1)))?;
            }
            "generic_name" => {
                node = node
                    .child_by_field_name("name")
                    .or_else(|| node.named_child(0))?;
            }
            "nullable_type"
            | "array_type"
            | "pointer_type"
            | "type"
            | "simple_base_type"
            | "primary_constructor_base_type" => {
                node = node
                    .child_by_field_name("type")
                    .or_else(|| node.named_child(0))?;
            }
            _ => return None,
        }
    }
}

pub(crate) fn csharp_type_leftmost_identifier(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "identifier" | "predefined_type" => return Some(node),
            "qualified_name" | "alias_qualified_name" | "member_access_expression" => {
                node = node
                    .child_by_field_name("qualifier")
                    .or_else(|| node.child_by_field_name("alias"))
                    .or_else(|| node.child_by_field_name("expression"))
                    .or_else(|| node.named_child(0))?;
            }
            "generic_name" => {
                node = node
                    .child_by_field_name("name")
                    .or_else(|| node.named_child(0))?;
            }
            "nullable_type"
            | "array_type"
            | "pointer_type"
            | "type"
            | "simple_base_type"
            | "primary_constructor_base_type" => {
                node = node
                    .child_by_field_name("type")
                    .or_else(|| node.named_child(0))?;
            }
            _ => return None,
        }
    }
}

fn same_csharp_node(left: Node<'_>, right: Node<'_>) -> bool {
    left.start_byte() == right.start_byte() && left.end_byte() == right.end_byte()
}

/// Return the structured name node when `node` is inside a C# attribute's name.
/// Identifiers in an attribute argument deliberately do not count.
pub(crate) fn csharp_attribute_name_node(node: Node<'_>) -> Option<Node<'_>> {
    let start = node.start_byte();
    let end = node.end_byte();
    let mut current = node;
    loop {
        if current.kind() == "attribute" {
            return current
                .child_by_field_name("name")
                .filter(|name| name.start_byte() <= start && end <= name.end_byte());
        }
        current = current.parent()?;
    }
}

/// C# attribute lookup considers both the written type name and the same name
/// with `Attribute` appended to its terminal AST segment. A verbatim identifier
/// suppresses the suffix form.
pub(crate) fn csharp_attribute_type_names(name: Node<'_>, source: &str) -> Vec<String> {
    let exact = csharp_type_node_identity_with_terminal_suffix(name, source, "", true);
    if exact.is_empty() {
        return Vec::new();
    }

    let verbatim = csharp_attribute_terminal_name(name, source)
        .is_some_and(|terminal| terminal.starts_with('@'));
    if verbatim {
        return vec![exact];
    }

    let suffixed = csharp_type_node_identity_with_terminal_suffix(name, source, "Attribute", false);
    if suffixed == exact {
        vec![exact]
    } else {
        vec![exact, suffixed]
    }
}

pub(crate) fn csharp_attribute_terminal_name<'a>(
    name: Node<'_>,
    source: &'a str,
) -> Option<&'a str> {
    let mut terminal = name;
    while let Some(next) = match terminal.kind() {
        "qualified_name" | "alias_qualified_name" => terminal
            .child_by_field_name("name")
            .or_else(|| terminal.named_child(terminal.named_child_count().saturating_sub(1))),
        "generic_name" => terminal
            .child_by_field_name("name")
            .or_else(|| terminal.named_child(0)),
        _ => None,
    } {
        terminal = next;
    }
    source
        .get(terminal.start_byte()..terminal.end_byte())
        .map(str::trim)
        .filter(|terminal| !terminal.is_empty())
}

#[derive(Clone, Copy)]
pub(crate) struct CSharpMemberName<'tree> {
    pub(crate) identifier: Node<'tree>,
    pub(crate) explicit_generic_arity: Option<usize>,
    pub(crate) type_arguments: Option<Node<'tree>>,
}

#[derive(Clone, Copy)]
pub(crate) struct CSharpConditionalMemberAccess<'tree> {
    pub(crate) receiver: Node<'tree>,
    pub(crate) binding: Node<'tree>,
    pub(crate) name: Node<'tree>,
}

pub(crate) fn csharp_conditional_member_access(
    node: Node<'_>,
) -> Option<CSharpConditionalMemberAccess<'_>> {
    if node.kind() != "conditional_access_expression" {
        return None;
    }
    let receiver = node.child_by_field_name("condition")?;
    let mut cursor = node.walk();
    let binding = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "member_binding_expression")?;
    let name = binding.child_by_field_name("name")?;
    Some(CSharpConditionalMemberAccess {
        receiver,
        binding,
        name,
    })
}

pub(crate) fn csharp_member_name(node: Node<'_>) -> Option<CSharpMemberName<'_>> {
    match node.kind() {
        "identifier" => Some(CSharpMemberName {
            identifier: node,
            explicit_generic_arity: None,
            type_arguments: None,
        }),
        "generic_name" => {
            let identifier = node
                .child_by_field_name("name")
                .or_else(|| node.named_child(0))?;
            let type_arguments = node.child_by_field_name("type_arguments").or_else(|| {
                let mut cursor = node.walk();
                node.named_children(&mut cursor)
                    .find(|child| child.kind() == "type_argument_list")
            })?;
            Some(CSharpMemberName {
                identifier,
                explicit_generic_arity: Some(type_arguments.named_child_count()),
                type_arguments: Some(type_arguments),
            })
        }
        _ => None,
    }
}

pub(crate) fn csharp_unqualified_invocation_for_name(
    identifier: Node<'_>,
) -> Option<(Node<'_>, Option<usize>)> {
    let (function, explicit_generic_arity) = identifier
        .parent()
        .filter(|parent| parent.kind() == "generic_name")
        .and_then(|generic_name| {
            let name = csharp_member_name(generic_name)?;
            (name.identifier == identifier).then_some((generic_name, name.explicit_generic_arity))
        })
        .unwrap_or((identifier, None));
    let invocation = function.parent()?;
    (invocation.kind() == "invocation_expression"
        && invocation.child_by_field_name("function") == Some(function))
    .then_some((invocation, explicit_generic_arity))
}

pub(crate) fn csharp_signature_arity(signature: Option<&str>) -> usize {
    let Some(signature) = signature else {
        return 0;
    };
    let inner = signature
        .split_once('(')
        .and_then(|(_, rest)| rest.split_once(')').map(|(inner, _)| inner))
        .unwrap_or(signature)
        .trim();
    if inner.is_empty() {
        return 0;
    }
    count_top_level_comma_separated(inner)
}

pub(crate) fn csharp_method_generic_arity(signature: Option<&str>) -> usize {
    signature
        .and_then(|signature| signature.strip_prefix('`'))
        .and_then(|signature| signature.split_once('(').map(|(arity, _)| arity))
        .and_then(|arity| arity.parse().ok())
        .unwrap_or(0)
}

pub(crate) fn csharp_callable_arity(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> CallableArity {
    analyzer
        .signature_metadata(unit)
        .into_iter()
        .find_map(|metadata| metadata.callable_arity())
        .unwrap_or_else(|| CallableArity::exact(csharp_signature_arity(unit.signature())))
}

pub(crate) fn csharp_signature_return_type(signature: &str, name: &str) -> Option<String> {
    type_text_before_name(signature, name)
}

fn type_text_before_name(signature: &str, name: &str) -> Option<String> {
    let before_name = signature.trim().rsplit_once(name)?.0.trim();
    let before_name = before_name.trim_end_matches(|ch: char| ch == '?' || ch.is_whitespace());
    let type_text = before_name
        .split_whitespace()
        .rfind(|part| !member_modifier(part))?;
    let type_text = normalize_csharp_type_fragment(type_text);
    (!type_text.is_empty()).then_some(type_text)
}

fn member_modifier(part: &str) -> bool {
    matches!(
        part,
        "public"
            | "private"
            | "protected"
            | "internal"
            | "static"
            | "readonly"
            | "volatile"
            | "const"
            | "new"
            | "virtual"
            | "override"
            | "abstract"
            | "sealed"
            | "required"
    )
}

pub(crate) fn normalize_csharp_type_fragment(reference: &str) -> String {
    let trimmed = reference.trim();
    let without_nullable = trimmed.trim_end_matches('?').trim();
    let without_arrays = without_nullable.trim_end_matches("[]").trim();
    without_arrays
        .split('<')
        .next()
        .unwrap_or(without_arrays)
        .trim()
        .to_string()
}

fn count_top_level_comma_separated(text: &str) -> usize {
    if text.trim().is_empty() {
        return 0;
    }

    let mut count = 1;
    let mut angle_depth: usize = 0;
    let mut paren_depth: usize = 0;
    let mut bracket_depth: usize = 0;
    let mut brace_depth: usize = 0;
    let mut string_quote: Option<char> = None;
    let mut escaped = false;

    for ch in text.chars() {
        if let Some(quote) = string_quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote {
                string_quote = None;
            }
            continue;
        }

        match ch {
            '"' | '\'' => string_quote = Some(ch),
            '<' => angle_depth = angle_depth.saturating_add(1),
            '>' if angle_depth > 0 => angle_depth -= 1,
            '(' => paren_depth = paren_depth.saturating_add(1),
            ')' if paren_depth > 0 => paren_depth -= 1,
            '[' => bracket_depth = bracket_depth.saturating_add(1),
            ']' if bracket_depth > 0 => bracket_depth -= 1,
            '{' => brace_depth = brace_depth.saturating_add(1),
            '}' if brace_depth > 0 => brace_depth -= 1,
            ',' if angle_depth == 0
                && paren_depth == 0
                && bracket_depth == 0
                && brace_depth == 0 =>
            {
                count += 1;
            }
            _ => {}
        }
    }

    count
}

impl TestDetectionProvider for CSharpAnalyzer {}

impl IAnalyzer for CSharpAnalyzer {
    fn begin_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.inner.begin_query(context);
    }

    fn end_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.inner.end_query(context);
    }

    fn top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        self.inner.top_level_declarations(file)
    }

    fn summary_file_projection(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<crate::analyzer::SummaryFileProjection>> {
        self.inner.summary_file_projection(file)
    }

    fn analyzed_files(&self) -> Vec<ProjectFile> {
        self.inner.analyzed_files()
    }

    fn indexed_source(&self, file: &ProjectFile) -> Option<String> {
        self.inner.indexed_source(file)
    }

    fn indexed_source_matches(&self, file: &ProjectFile, source: &str) -> bool {
        self.inner.indexed_source_matches(file, source)
    }

    fn is_analyzed(&self, file: &ProjectFile) -> bool {
        self.inner.is_analyzed(file)
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.all_declarations()
    }

    fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.inner.declarations(file)
    }

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.definitions(fq_name)
    }

    fn reset_global_usage_definition_index_build_count_for_test(&self) {
        self.inner
            .reset_global_usage_definition_index_build_count_for_test();
    }

    fn global_usage_definition_index_build_count_for_test(&self) -> usize {
        self.inner
            .global_usage_definition_index_build_count_for_test()
    }

    fn reset_definition_candidates_query_count_for_test(&self) {
        self.inner
            .reset_definition_candidates_query_count_for_test();
    }

    fn definition_candidates_query_count_for_test(&self) -> usize {
        self.inner.definition_candidates_query_count_for_test()
    }

    fn reset_full_declaration_scan_count_for_test(&self) {
        self.inner.reset_full_declaration_scan_count_for_test();
    }

    fn full_declaration_scan_count_for_test(&self) -> usize {
        self.inner.full_declaration_scan_count_for_test()
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    fn candidate_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test() + self.inner.bulk_hydration_count_for_test()
    }

    fn global_usage_definition_index(&self) -> &crate::analyzer::GlobalUsageDefinitionIndex {
        self.inner.global_usage_definition_index()
    }

    fn usage_facts_index(&self) -> &UsageFactsIndex {
        self.inner.usage_facts_index()
    }

    fn structural_search_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralSearchProvider> {
        self.inner.structural_search_providers()
    }

    fn snapshot_caches(&self) -> Option<&crate::analyzer::AnalyzerSnapshotCaches> {
        Some(self.inner.snapshot_caches())
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.direct_children(code_unit)
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.inner.structural_parent_of(code_unit)
    }

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.import_statements(file)
    }

    fn ranges(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range> {
        self.inner.ranges(code_unit)
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.inner.compute_cognitive_complexities(file)
    }

    fn signatures(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.signatures(code_unit)
    }

    fn signature_metadata(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        self.inner.signature_metadata(code_unit)
    }

    fn get_analyzed_files(&self) -> BTreeSet<ProjectFile> {
        self.inner.get_analyzed_files()
    }

    fn languages(&self) -> BTreeSet<Language> {
        self.inner.languages()
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        let external_index = if changed_files
            .iter()
            .any(dependency_discovery::is_csharp_dependency_input)
        {
            Arc::new(std::sync::OnceLock::new())
        } else {
            self.external_index.clone()
        };
        Self {
            inner: self.inner.update(changed_files),
            memo_caches: Arc::new(CSharpMemoCaches::new(self.memo_caches.budget_bytes())),
            csharp_config: self.csharp_config.clone(),
            external_index,
        }
    }

    fn update_all(&self) -> Self {
        Self {
            inner: self.inner.update_all(),
            memo_caches: Arc::new(CSharpMemoCaches::new(self.memo_caches.budget_bytes())),
            csharp_config: self.csharp_config.clone(),
            external_index: Arc::new(std::sync::OnceLock::new()),
        }
    }

    fn project(&self) -> &dyn Project {
        self.inner.project()
    }

    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        self.inner.get_all_declarations()
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        self.inner.get_definitions(fq_name)
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.inner.extract_call_receiver(reference)
    }

    fn enclosing_code_unit(
        &self,
        file: &ProjectFile,
        range: &crate::analyzer::Range,
    ) -> Option<CodeUnit> {
        self.inner.enclosing_code_unit(file, range)
    }

    fn enclosing_code_unit_for_lines(
        &self,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit> {
        self.inner
            .enclosing_code_unit_for_lines(file, start_line, end_line)
    }

    fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool {
        self.inner.is_access_expression(file, start_byte, end_byte)
    }

    fn find_nearest_declaration(
        &self,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
        ident: &str,
    ) -> Option<crate::analyzer::DeclarationInfo> {
        self.inner
            .find_nearest_declaration(file, start_byte, end_byte, ident)
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        self.inner.get_skeleton(code_unit)
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        self.inner.get_skeleton_header(code_unit)
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        self.inner.get_source(code_unit, include_comments)
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        self.inner.get_sources(code_unit, include_comments)
    }

    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit> {
        self.inner.search_definitions(pattern, auto_quote)
    }

    fn lookup_candidates_by_short_name(&self, symbol: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_candidates_by_short_name(symbol)
    }

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.declaration_candidates_by_identifier(identifier)
    }

    fn search_symbol_candidates(
        &self,
        pattern: &str,
        auto_quote: bool,
    ) -> Vec<crate::analyzer::SearchSymbolCandidate> {
        self.inner.search_symbol_candidates(pattern, auto_quote)
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        if !self.contains_tests(file) || file_language(file) != Language::CSharp {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_csharp_test_assertion_smells(file, &source, &weights)
    }

    fn find_structural_clone_smells(
        &self,
        file: &ProjectFile,
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        self.find_structural_clone_smells_for_files(std::slice::from_ref(file), weights)
    }

    fn find_structural_clone_smells_for_files(
        &self,
        files: &[ProjectFile],
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        let requested_files: Vec<ProjectFile> = files
            .iter()
            .filter(|file| file_language(file) == Language::CSharp)
            .cloned()
            .collect();
        if requested_files.is_empty() {
            return Vec::new();
        }

        let all_candidates: Vec<CloneCandidateProfile> = self
            .get_all_declarations()
            .into_iter()
            .filter(|code_unit| {
                code_unit.is_function() && file_language(code_unit.source()) == Language::CSharp
            })
            .filter_map(|code_unit| build_csharp_clone_candidate_data(self, &code_unit, weights))
            .map(|candidate| CloneCandidateProfile::create(candidate, weights))
            .collect();
        if all_candidates.is_empty() {
            return Vec::new();
        }

        detect_structural_clone_smells(
            &requested_files,
            all_candidates,
            weights,
            refine_csharp_clone_similarity,
        )
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        Some(self)
    }
}
