//! The analyzer-resident products Ruby's language logic resolves through.
//!
//! `RubyAnalyzer` owns three moka caches, nine `Arc<OnceLock<..>>` cells and one
//! `PoolSafeMemo`; every one of them stays in `brokk-bifrost-analysis` because
//! `IAnalyzer::update`/`update_all` rebuild the analyzer wholesale through
//! `Self::from_inner`. What crosses the crate line is the *decision* that fills
//! each cell -- the builders in [`crate::imports`], [`crate::mixins`] and
//! [`crate::hierarchy`] -- plus this trait, which is how a free function reaches
//! back for a memoized product without naming the analyzer type.
//!
//! Two members are load-bearing beyond their signature:
//!
//! * [`RubySource::forward_owner_relation_facts`] is the one accessor with no
//!   landed precedent. Its body reads `TreeSitterAnalyzer::fetch_file_state`,
//!   whose `Arc<FileState>` is crate-private to analysis, so it stays there and
//!   hands the decoded facts across (the Py-2 `collect_bounded` precedent).
//! * [`RubySource::ruby_all_files`] is `TreeSitterAnalyzer::all_files`, i.e. the
//!   analyzed *live* file set. `CodeUnitIndex::analyzed_files` is a different
//!   query, so this is spelled out rather than inferred from the supertrait.

use crate::mixins::RubyOwnerRelationFact;
use brokk_bifrost_core::analyzer::capabilities::{ImportAnalysisProvider, TypeHierarchyProvider};
use brokk_bifrost_core::analyzer::model::RubyMethodDispatchMode;
use brokk_bifrost_core::analyzer::type_relations::{TypeRelation, TypeRelationKind};
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::sync::Arc;

pub trait RubySource: CodeUnitIndex + TypeHierarchyProvider + ImportAnalysisProvider {
    /// The analyzed live file set (`TreeSitterAnalyzer::all_files`).
    fn ruby_all_files(&self) -> Vec<ProjectFile>;

    /// Workspace-wide `autoload :Const, "path"` edges, keyed by the `$`-joined
    /// constant name. Built by [`crate::imports::build_autoload_constant_files`].
    fn autoload_constant_files(&self) -> &HashMap<String, HashSet<ProjectFile>>;

    /// Whether `Gemfile`/`Gemfile.lock` declare rails or zeitwerk. Built by
    /// [`crate::imports::detect_zeitwerk_autoload_conventions`].
    fn has_zeitwerk_autoload_conventions(&self) -> bool;

    fn zeitwerk_autoload_files(&self) -> &HashSet<ProjectFile>;

    fn zeitwerk_consumer_files(&self) -> &HashSet<ProjectFile>;

    fn zeitwerk_autoload_code_units(&self) -> &HashSet<CodeUnit>;

    /// `required_files` inverted over the whole workspace, memoized through the
    /// analyzer's `PoolSafeMemo`.
    fn reverse_import_index(&self) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>;

    /// The resolved `include`/`prepend`/`extend` graph. Built by
    /// [`crate::mixins::ruby_collect_mixin_relations`].
    fn mixin_relations(&self) -> &[TypeRelation];

    /// Built by [`build_ruby_semantic_facts`].
    fn semantic_facts(&self) -> &RubySemanticFacts;

    /// Class/module declarations indexed by trailing identifier. Built by
    /// [`crate::hierarchy::build_ruby_types_by_identifier`].
    fn types_by_identifier(&self) -> &HashMap<String, Vec<CodeUnit>>;

    /// The persisted per-method dispatch mode, defaulting to `Instance`.
    fn method_dispatch_mode(&self, unit: &CodeUnit) -> RubyMethodDispatchMode;

    /// The decoded superclass and mixin relations declared by `owner`, read out
    /// of the analyzer's persisted per-file state. See this module's note.
    fn forward_owner_relation_facts(&self, owner: &CodeUnit) -> Vec<RubyOwnerRelationFact>;
}

/// The workspace-wide ancestry and mixin projection every proven method or
/// constant resolution reads. Populated only for a target-scoped scan; the
/// target-free lookup path resolves the same questions forward, per owner.
pub struct RubySemanticFacts {
    pub ancestors: HashMap<String, HashSet<String>>,
    pub mixin_included_owners: HashMap<String, Vec<String>>,
    pub mixin_prepended_owners: HashMap<String, Vec<String>>,
    pub mixin_class_owners: HashMap<String, Vec<String>>,
}

pub fn build_ruby_semantic_facts(ruby: &dyn RubySource) -> RubySemanticFacts {
    let mut ancestors = HashMap::default();
    let mut mixin_included_owners: HashMap<String, Vec<String>> = HashMap::default();
    let mut mixin_prepended_owners: HashMap<String, Vec<String>> = HashMap::default();
    let mut mixin_class_owners: HashMap<String, Vec<String>> = HashMap::default();

    for unit in ruby
        .all_declarations()
        .filter(|unit| unit.is_class() || unit.is_module())
    {
        let direct = ruby
            .get_direct_ancestors(&unit)
            .into_iter()
            .map(|ancestor| ancestor.fq_name())
            .collect();
        ancestors.insert(unit.fq_name(), direct);
    }

    for relation in ruby.mixin_relations() {
        let entry = match relation.kind {
            TypeRelationKind::MixinInclude => &mut mixin_included_owners,
            TypeRelationKind::MixinPrepend => &mut mixin_prepended_owners,
            TypeRelationKind::MixinExtend => &mut mixin_class_owners,
            _ => continue,
        };
        push_ordered_mixin(entry, relation.from.fq_name(), relation.to.fq_name());
    }

    RubySemanticFacts {
        ancestors,
        mixin_included_owners,
        mixin_prepended_owners,
        mixin_class_owners,
    }
}

fn push_ordered_mixin(index: &mut HashMap<String, Vec<String>>, from: String, to: String) {
    let owners = index.entry(from).or_default();
    if !owners.contains(&to) {
        owners.push(to);
    }
}
