//! Namespace-alias binding shared by forward and inverse C++ type lookup.
//!
//! `namespace name = target;` introduces no declaration of its own: it rebinds
//! a qualifier. Each definition is a typed source fact of the file that writes
//! it ([`CppNamespaceAliasFact`]); this module is the one resolver that reads
//! those facts. Both lookup directions reach it through
//! `resolve_type_components_in_authoritative_scope`, so a forward edge and an
//! inverse reference follow the same binding.
//!
//! A definition binds a written qualifier component when, at the reference:
//! - its name and scope match: a namespace-scope alias at the lexical tier
//!   that unqualified lookup reaches (or inside the namespace a qualified
//!   lookup names), or a block-scope alias whose block contains the reference;
//! - it is earlier in source order (for a chained alias, earlier than the
//!   alias that names it);
//! - its guards hold at the reference by the declaration-site rule.
//!
//! A definition whose guards the reference neither proves nor contradicts,
//! whose target has no structured path, or whose sites disagree leaves the
//! binding explicitly unresolved rather than falling back to the written
//! spelling.
//!
//! [`CppNamespaceAliasFact`]: brokk_bifrost_core::analyzer::cpp_facts::CppNamespaceAliasFact

use super::resolver::{
    PreprocessorGuard, VisibilityIndex, merge_preprocessor_guards, preprocessor_guard_environment,
};
use crate::source_context::cpp_guard_set_to_runtime;
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

/// One namespace alias definition in a source file visible from the root.
#[derive(Debug)]
pub struct NamespaceAliasSite {
    source: ProjectFile,
    start: usize,
    end: usize,
    target: Option<Vec<String>>,
    target_global: bool,
    namespace: Vec<String>,
    block: Option<(usize, usize)>,
    guards: Option<HashSet<PreprocessorGuard>>,
}

impl NamespaceAliasSite {
    fn same_target(&self, other: &Self) -> bool {
        self.target == other.target
            && self.target_global == other.target_global
            && self.namespace == other.namespace
    }
}

/// The namespace aliases of one root's visible source files, by alias name.
pub type NamespaceAliasCell =
    Arc<super::resolver::VisibilityCell<Arc<HashMap<String, Vec<NamespaceAliasSite>>>>>;

/// How the namespace aliases in effect at a reference rebind its qualifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceQualifierBinding {
    /// No namespace alias binds a qualifier component at the reference.
    Unaliased,
    /// The qualifier names an alias whose target, followed through any alias
    /// chain, is established: look `components` up from `lexical_scope`, the
    /// scope of the last alias in the chain.
    Bound {
        components: Vec<String>,
        global: bool,
        lexical_scope: Vec<String>,
        depth: usize,
    },
    /// The qualifier names an alias whose target cannot be established here.
    Unresolved { depth: usize },
}

impl NamespaceQualifierBinding {
    /// The lexical depth at which the first alias binds: the length of the
    /// scope that declares it, or one more than the reference's scope for a
    /// block-scope alias. An ordinary name found at a deeper tier shadows it.
    pub fn depth(&self) -> Option<usize> {
        match self {
            Self::Unaliased => None,
            Self::Bound { depth, .. } | Self::Unresolved { depth } => Some(*depth),
        }
    }
}

/// How many alias hops one binding follows before it reports the chain as
/// unresolved; a cycle (`namespace a = b; namespace b = a;`) ends here.
const MAX_NAMESPACE_ALIAS_HOPS: usize = 32;

enum SiteState {
    InEffect,
    Possible,
    Hidden,
}

struct AliasLookup<'r, 'tree> {
    file: &'r ProjectFile,
    reference: Node<'tree>,
    sites: &'r HashMap<String, Vec<NamespaceAliasSite>>,
    raw_reference_guards: Option<HashSet<PreprocessorGuard>>,
}

impl VisibilityIndex<'_> {
    /// Rebind the qualifier of the type name `components`, written at
    /// `reference` in `file` with the given lexical scope, through the
    /// namespace aliases in effect there.
    pub fn bind_namespace_qualifier(
        &self,
        file: &ProjectFile,
        reference: Node<'_>,
        components: &[String],
        global: bool,
        lexical_scope: &[String],
    ) -> NamespaceQualifierBinding {
        if components.len() < 2 {
            return NamespaceQualifierBinding::Unaliased;
        }
        let cell = self.namespace_alias_cell(file);
        let sites = cell.get_or_init(|| Arc::new(self.collect_namespace_alias_sites(file)));
        if !components[..components.len() - 1]
            .iter()
            .any(|component| sites.contains_key(component))
        {
            return NamespaceQualifierBinding::Unaliased;
        }
        let lookup = AliasLookup {
            file,
            reference,
            sites: &sites,
            raw_reference_guards: self
                .cpp()
                .prepared_syntax(self.token(), file)
                .and_then(|prepared| preprocessor_guard_environment(reference, prepared.source())),
        };
        self.bind_qualifier(
            &lookup,
            components,
            global,
            lexical_scope,
            (file, reference.start_byte()),
            MAX_NAMESPACE_ALIAS_HOPS,
        )
    }

    fn collect_namespace_alias_sites(
        &self,
        root: &ProjectFile,
    ) -> HashMap<String, Vec<NamespaceAliasSite>> {
        let mut sites: HashMap<String, Vec<NamespaceAliasSite>> = HashMap::default();
        for source in self.visible_source_files(root) {
            let Some(facts) = self.cpp().declaration_source_facts(self.token(), &source) else {
                continue;
            };
            for alias in &facts.facts.namespace_aliases {
                let range = facts.source.occurrence(alias.occurrence).range;
                sites
                    .entry(alias.name.clone())
                    .or_default()
                    .push(NamespaceAliasSite {
                        source: source.clone(),
                        start: range.start_byte,
                        end: range.end_byte,
                        target: alias.target.clone(),
                        target_global: alias.target_global,
                        namespace: alias.namespace.clone(),
                        block: alias.block.map(|block| {
                            let range = facts.source.occurrence(block).range;
                            (range.start_byte, range.end_byte)
                        }),
                        guards: alias.guards.as_ref().and_then(cpp_guard_set_to_runtime),
                    });
            }
        }
        sites
    }

    /// Bind the first alias among the qualifier components of `components`,
    /// looked up from `lexical_scope` at `position`, the reference itself or
    /// the alias definition whose target is being followed.
    fn bind_qualifier(
        &self,
        lookup: &AliasLookup<'_, '_>,
        components: &[String],
        global: bool,
        lexical_scope: &[String],
        position: (&ProjectFile, usize),
        hops: usize,
    ) -> NamespaceQualifierBinding {
        let qualifier = &components[..components.len() - 1];
        let precedes =
            |site: &NamespaceAliasSite| site.source != *position.0 || site.end <= position.1;
        if !global {
            // A block-scope alias is closer than any namespace-scope name.
            let block_sites = lookup
                .sites
                .get(&qualifier[0])
                .into_iter()
                .flatten()
                .filter(|site| {
                    site.block.is_some_and(|(start, end)| {
                        site.source == *position.0 && start <= position.1 && position.1 < end
                    }) && precedes(site)
                        && lexical_scope.starts_with(&site.namespace)
                });
            if let Some(innermost) = block_sites.clone().filter_map(|site| site.block).max() {
                let candidates = block_sites
                    .filter(|site| site.block == Some(innermost))
                    .collect::<Vec<_>>();
                return self.bind_through(
                    lookup,
                    &candidates,
                    components,
                    0,
                    lexical_scope.len() + 1,
                    hops,
                );
            }
        }
        let innermost_tier = if global { 0 } else { lexical_scope.len() };
        for tier in (0..=innermost_tier).rev() {
            let mut owner = lexical_scope[..tier].to_vec();
            for (index, name) in qualifier.iter().enumerate() {
                let candidates = lookup
                    .sites
                    .get(name)
                    .into_iter()
                    .flatten()
                    .filter(|site| {
                        site.block.is_none() && site.namespace == owner && precedes(site)
                    })
                    .collect::<Vec<_>>();
                if !candidates.is_empty() {
                    match self.bind_through(lookup, &candidates, components, index, tier, hops) {
                        NamespaceQualifierBinding::Unaliased => {}
                        binding => return binding,
                    }
                }
                owner.push(name.clone());
            }
        }
        NamespaceQualifierBinding::Unaliased
    }

    /// Bind `components[index]` through the same-scope definitions in
    /// `candidates`, then follow the target's own qualifier from the alias's
    /// scope and position.
    fn bind_through(
        &self,
        lookup: &AliasLookup<'_, '_>,
        candidates: &[&NamespaceAliasSite],
        components: &[String],
        index: usize,
        depth: usize,
        hops: usize,
    ) -> NamespaceQualifierBinding {
        let mut bound: Option<&NamespaceAliasSite> = None;
        let mut unresolved = false;
        for site in candidates {
            match self.namespace_alias_site_state(lookup, site) {
                SiteState::Hidden => {}
                SiteState::Possible => unresolved = true,
                SiteState::InEffect => match bound {
                    None => bound = Some(site),
                    Some(previous) if previous.same_target(site) => {}
                    Some(_) => unresolved = true,
                },
            }
        }
        if unresolved {
            return NamespaceQualifierBinding::Unresolved { depth };
        }
        let Some(site) = bound else {
            return NamespaceQualifierBinding::Unaliased;
        };
        let (Some(target), Some(hops)) = (&site.target, hops.checked_sub(1)) else {
            return NamespaceQualifierBinding::Unresolved { depth };
        };
        let mut rebound = target.clone();
        rebound.extend_from_slice(&components[index + 1..]);
        match self.bind_qualifier(
            lookup,
            &rebound,
            site.target_global,
            &site.namespace,
            (&site.source, site.start),
            hops,
        ) {
            NamespaceQualifierBinding::Unaliased => NamespaceQualifierBinding::Bound {
                components: rebound,
                global: site.target_global,
                lexical_scope: site.namespace.clone(),
                depth,
            },
            NamespaceQualifierBinding::Bound {
                components,
                global,
                lexical_scope,
                ..
            } => NamespaceQualifierBinding::Bound {
                components,
                global,
                lexical_scope,
                depth,
            },
            NamespaceQualifierBinding::Unresolved { .. } => {
                NamespaceQualifierBinding::Unresolved { depth }
            }
        }
    }

    fn namespace_alias_site_state(
        &self,
        lookup: &AliasLookup<'_, '_>,
        site: &NamespaceAliasSite,
    ) -> SiteState {
        let Some(guards) = &site.guards else {
            return SiteState::Possible;
        };
        if self.binding_site_visible_at_reference(
            lookup.file,
            &site.source,
            site.end,
            guards,
            lookup.reference,
        ) {
            return SiteState::InEffect;
        }
        // A definition the reference reaches only under guards it neither
        // proves nor contradicts is a live alternative, not an absence.
        let reachable_in_order =
            site.source != *lookup.file || site.end <= lookup.reference.start_byte();
        if reachable_in_order
            && !guards.is_empty()
            && lookup
                .raw_reference_guards
                .as_ref()
                .is_some_and(|active| merge_preprocessor_guards(guards, active).is_some())
        {
            SiteState::Possible
        } else {
            SiteState::Hidden
        }
    }
}
