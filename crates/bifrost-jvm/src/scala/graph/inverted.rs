//! Whole-workspace inverted edge builder for Scala.
//!
//! Walks each file once and resolves every reference to the callee fqn it names,
//! via the shared [`build_edges`] driver. Scala has no single `resolve_type_name`
//! primitive, so name->fqn resolution is rebuilt here by mirroring the forward
//! scanner's visibility model: a per-file [`NameResolver`] maps a
//! source-visible type/object name to the analyzer's own fqn, honoring the file's
//! package and its imports. A [`LocalInferenceEngine`] seeded with typed params
//! and `val x = new Foo()` lets a method call's receiver be typed:
//!
//! - a type reference (`x: Foo`, `new Foo`, `def f(): Foo`) resolves to the type;
//! - `recv.method(..)` types `recv` to `Owner`, giving `Owner.method`;
//! - `this`/an unqualified `method(..)` attributes to the enclosing class.
//!
//! Scala object fqns keep their `$` object-encoding suffix (`example.Helpers$`,
//! method `example.Helpers$.help`), so type/object fqns come straight from the
//! analyzer's declarations rather than being rebuilt from `package.name` text —
//! a string-rebuilt name would drop the `$` and silently match no node. The
//! enclosing class is taken from a per-file class-range index (the analyzer's own
//! fqns) so `this`/unqualified calls attribute to the right class (and the right
//! `$`-encoded object). Receivers needing return-type inference (method chains)
//! are an unhandled recall gap, not a wrong edge.

use super::local::{
    ScalaLocalBinding, precise_scala_binding, seed_scala_binding,
    seed_scala_binding_with_receiver_declaration,
};
use super::namespace::{
    ScalaDirectAncestorResolution, ScalaQualifiedTypeRootBinding, ScalaQualifiedTypeRootResolution,
    ScalaTypeNamespaceResolution, ScalaUnindexedTypeBinding, resolve_exact_lexical_type_namespace,
    scala_anonymous_instance_for_template, scala_nearest_unindexed_type_binding,
    scala_qualified_type_root, scala_type_reference_is_singleton,
};
use super::resolver::{
    preferred_scala_type, scala_builtin_type_name, scala_extension_receiver_matches_resolved,
    scala_literal_type_name, scala_normalized_fq_name,
};
use super::syntax::{
    ScalaCallSiteShape, ScalaCallableParameterList, ScalaCallableRole, ScalaCallableSiteRole,
    ScalaCallableUsePolicy, ScalaDeclaredResult, ScalaFunctionParameterShape,
    ScalaGenericOwnerSourceFacts, ScalaImportContextIndex, ScalaMethodValueContext,
    ScalaPackageContextIndex, ScalaParameterTypeIdentity, ScalaQualifiedStableTypeRole,
    ScalaSourceFacts, ScalaTypeExpressionPath, call_arities_for_reference,
    call_site_shape_for_reference, enclosing_template_declarations,
    intermediate_field_qualifier_reference, invocation_function_reference,
    is_bare_companion_method_value_reference, is_call_function_reference,
    is_constructor_like_reference, is_declaration_name, is_enclosing_template_qualifier_reference,
    is_extractor_reference, is_field_expression_value, is_identifier_node,
    is_infix_pattern_operator, is_owner_qualified_this, is_qualified_stable_root,
    is_scala_case_pattern_binder, is_scala_class_reference, is_scala_named_argument_assignment,
    is_scala_object_reference, is_semantic_call_argument, is_stable_type_qualifier,
    is_terminal_stable_field_reference, named_argument_invocation_owner, node_text,
    parenthesized_arity, qualified_stable_type_reference, resolve_stable_object_expression,
    scala_callable_alternative_is_candidate, scala_callable_alternative_matches,
    scala_callable_shape_matches, scala_definition_binder_names, scala_import_is_visible_at_byte,
    scala_pattern_binder_names, scala_source_facts, scala_union_type_alternative_paths,
    stable_identifier_prefix_reference, stable_identifier_reference, stable_path_segments,
    stable_type_prefix_reference, template_direct_term_member_named, template_self_types,
    terminal_invocation_owner_name,
};
use crate::scala::declarations::scala_class_parameter_field_keyword;
use crate::scala::graph_support::{
    ScalaCallableFactsIndex, ScalaDefinitionIndex, ScalaFileFacts, ScalaSource,
    ScalaWorkspaceSource,
};
use crate::scala::imports::scala_import_infos_from_node;
use crate::scala::supertypes::{
    ScalaSupertypeLookupPath, scala_supertype_lookup_nodes, scala_type_lookup_segments,
};
use crate::scala::wildcard_imports::{
    ScalaExplicitImportFacts, ScalaExplicitImportTier, ScalaWildcardOwnerFacts,
    resolve_scala_explicit_import_tier, resolve_scala_wildcard_import_environment,
    scala_enclosing_package_root_candidates, scala_import_path, scala_import_path_candidates,
};
use crate::scala::{
    scala_member_signature_arity, scala_nested_type_candidates, scala_short_name_terminal_segment,
    scala_simple_type_name,
};
use brokk_bifrost_core::analyzer::model::{
    CallableArity, CallableFacts, ImportInfo, ScalaExportInfo, ScalaExportSelector,
    SignatureMetadata,
};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::usages::inverted_edges::{
    ClassRangeIndex, FileEdgeScanInput, PerFileEdges, UsageReferenceKind, classify_reference_node,
};
use brokk_bifrost_core::analyzer::usages::local_inference::{
    LocalInferenceConfig, LocalInferenceEngine,
};
use brokk_bifrost_core::analyzer::usages::model::UsageHitKind;
use brokk_bifrost_core::analyzer::usages::same_owner::route_same_owner;
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, ProjectFile, Range};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::borrow::Borrow;
use std::sync::{Arc, Mutex, OnceLock};
use tree_sitter::{Node, Parser, Tree};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ScalaReferenceRole {
    Type,
    Callable,
    CompanionApplication,
    CompanionExtractor,
    CompanionValue,
    Field,
    StableObject,
    Override,
}

#[derive(Clone, Debug)]
pub enum ScalaResolvedReference {
    Exact(CodeUnit),
    Logical(String),
}

/// The receiver shape a [`ScalaLogicalOwnerMember`] event was seen through.
///
/// The Scala walk cannot know whether the foreign target is declared `static`;
/// it can only report how the site wrote the receiver. The sink pairs the two
/// (a static target matches only a `StaticOwner` event and vice versa), which
/// keeps an instance call like `sectionValue.read(..)` from matching the static
/// overload when both arities coincide. Java's legal-but-rare "static through
/// an instance" spelling stays unmatched, exactly as the retired duplicate
/// scanner behaved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalaLogicalReceiver {
    /// A value whose seeded or inferred type is the owner: `c.size()`.
    Instance,
    /// The owner type itself written as the receiver: `Config.of(..)`.
    StaticOwner,
}

/// A member reference proven up to a receiver *type* that has no Scala
/// declaration (the #1859 replacement channel for the retired duplicate
/// scanner). The owner is a fully qualified name the scan resolved
/// through the file's imports and the all-language definition index; it is
/// never a guessed bare name. Carried separately from
/// [`ScalaResolvedReference::Logical`] so the sink can match the owner's
/// normalized fqn against a target's receiver-owner set and the member name
/// independently, which is what subtype receiver matching needs.
pub struct ScalaLogicalOwnerMember<'a> {
    pub owner_fqn: &'a str,
    pub member: &'a str,
    pub role: ScalaReferenceRole,
    pub receiver: ScalaLogicalReceiver,
    pub call_shape: Option<&'a ScalaCallSiteShape>,
}

/// Same-owner policy (#1014 facet B / #1138): Scala's receiver shape is threaded
/// through this event pipeline via `hit_kind`.
///
/// The `ScalaScan` producer (which holds the call node) classifies a callable
/// reference whose receiver denotes the enclosing instance / own object —
/// explicit `this.m()`, an implicit bare `m()` resolved to an own or inherited
/// template member, or `Obj.m()` from within `Obj` — as
/// [`UsageHitKind::SelfReceiver`], while `super.m()` and a call through a
/// different variable (even one of the same type) stay [`UsageHitKind::Reference`].
/// The shared [`route_same_owner`] contract is honored at the two sinks:
/// the scan sink records the hit and lets the external surface exclude it (and
/// count it as a same-owner site), while the inverted [`ScalaEdgeSink`] routes a
/// same-owner reference to *unproven* inbound rather than a proven edge, so a
/// method reachable only through same-owner calls reads INCONCLUSIVE — uniform
/// with the other ten languages.
pub trait ScalaReferenceSink {
    fn may_match_name(&self, _name: &str) -> bool {
        true
    }

    /// An inverted scan may reject an import path before resolving its owners.
    /// Query sinks keep the default because their target-name frontier has
    /// additional alias semantics supplied by the query itself.
    fn may_match_import_terminal(&self, _name: &str) -> bool {
        true
    }

    fn register_imports(&mut self, _imports: &[ImportInfo]) {}

    fn record(
        &mut self,
        target: ScalaResolvedReference,
        role: ScalaReferenceRole,
        reference_kind: UsageReferenceKind,
        hit_kind: UsageHitKind,
        start: usize,
        end: usize,
    );

    #[allow(clippy::too_many_arguments)]
    fn record_callable(
        &mut self,
        target: ScalaResolvedReference,
        role: ScalaReferenceRole,
        call_shape: &ScalaCallSiteShape,
        reference_kind: UsageReferenceKind,
        hit_kind: UsageHitKind,
        start: usize,
        end: usize,
    ) {
        let _ = call_shape;
        self.record(target, role, reference_kind, hit_kind, start, end);
    }

    #[allow(clippy::too_many_arguments)]
    fn record_with_caller(
        &mut self,
        _caller: String,
        target: ScalaResolvedReference,
        role: ScalaReferenceRole,
        reference_kind: UsageReferenceKind,
        hit_kind: UsageHitKind,
        start: usize,
        end: usize,
    ) {
        self.record(target, role, reference_kind, hit_kind, start, end);
    }

    fn record_unproven_name(&mut self, _name: &str, _start: usize, _end: usize) {}

    fn record_import_name(
        &mut self,
        _imports: &[ImportInfo],
        _active_package: &str,
        _name: &str,
        _start: usize,
        _end: usize,
    ) {
    }

    #[allow(clippy::too_many_arguments)]
    fn record_exact_owner_member(
        &mut self,
        _owner: CodeUnit,
        _member: &str,
        _role: ScalaReferenceRole,
        _reference_kind: UsageReferenceKind,
        _hit_kind: UsageHitKind,
        _start: usize,
        _end: usize,
    ) {
    }

    /// A member reference whose receiver type resolved to a fully qualified
    /// name with no Scala declaration. Sinks that serve foreign (Java/Kotlin)
    /// targets override this; the default drops it, which keeps Scala-target
    /// catalogs and the edge build bit-identical.
    fn record_logical_owner_member(
        &mut self,
        _event: ScalaLogicalOwnerMember<'_>,
        _reference_kind: UsageReferenceKind,
        _hit_kind: UsageHitKind,
        _start: usize,
        _end: usize,
    ) {
    }

    fn should_stop(&self) -> bool {
        false
    }
}

type PackageTypeEntries = Arc<Vec<(String, CodeUnit)>>;
type CachedScalaSourceFacts = Arc<ScalaSourceFacts>;
type ScalaSourceFactsCell = Arc<OnceLock<CachedScalaSourceFacts>>;
pub type CachedCallableAlternatives = Arc<Vec<CallableAlternative>>;
type CallableAlternativesCell = Arc<OnceLock<CachedCallableAlternatives>>;
type ExtensionOwnerMemberKey = (String, String);
type ExtensionMethodEntries = Arc<Vec<ExtensionMethod>>;
type OverrideTargetEntries = Arc<Vec<CodeUnit>>;

#[derive(Clone)]
struct ScalaExportEdge {
    exporter_fqn: String,
    source_owner_fqn: String,
    selectors: Vec<ScalaExportSelector>,
}

type ExportedMemberBindings = HashMap<String, HashSet<String>>;

pub enum MemberReturnResolution {
    NoMatch,
    Unresolved,
    Resolved(String),
}

pub enum BareMemberResolution {
    NoMatch,
    Unresolved,
    Resolved(Vec<CodeUnit>),
}

pub enum FieldResolution {
    NoMatch,
    Unresolved,
    Resolved(ResolvedField),
}

pub struct ResolvedField {
    pub declaration: CodeUnit,
    pub declared_type: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TypeApplicationRole {
    ExplicitConstructor,
    BareApplication,
    Extractor,
}

pub struct TypeApplicationResolution {
    pub type_target: Option<CodeUnit>,
    pub callable_targets: Vec<CodeUnit>,
    pub value_result: Option<ScalaValueOwner>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScalaValueOwner {
    Exact(CodeUnit),
    Logical(String),
}

struct ScalaCallableValueResolution {
    callable_targets: Vec<CodeUnit>,
    value_result: Option<ScalaValueOwner>,
}

enum ScalaCallableTierResolution {
    NoApplicableCallable,
    Applicable(Option<ScalaCallableValueResolution>),
}

enum ScalaApplyValueResolution {
    NoDeclaration,
    NoApplicableCallable,
    Authoritative(Option<ScalaCallableValueResolution>),
}

/// Every type-namespace declaration the project exposes, indexed for the
/// per-file name->fqn rebuild. Built once and shared across all files' scans.
pub struct ProjectTypes {
    index: Arc<dyn ScalaDefinitionIndex>,
    type_aliases: Arc<HashSet<CodeUnit>>,
    facts: Arc<dyn ScalaCallableFactsIndex>,
    direct_ancestors_by_owner: Option<Arc<HashMap<String, Vec<CodeUnit>>>>,
    direct_ancestors_by_unit: Option<Arc<HashMap<CodeUnit, Vec<CodeUnit>>>>,
    ambiguous_direct_ancestor_owners: Option<Arc<HashSet<CodeUnit>>>,
    structural_parent_by_unit: Option<Arc<HashMap<CodeUnit, CodeUnit>>>,
    scala_trait_fqns: Option<Arc<HashSet<String>>>,
    package_types_by_package: Mutex<HashMap<String, PackageTypeEntries>>,
    package_objects_by_package: Mutex<HashMap<String, PackageTypeEntries>>,
    nested_types_by_owner: Mutex<HashMap<String, PackageTypeEntries>>,
    nested_objects_by_owner: Mutex<HashMap<String, PackageTypeEntries>>,
    wildcard_members_by_owner: Mutex<HashMap<String, PackageTypeEntries>>,
    source_facts_by_file: Mutex<HashMap<ProjectFile, ScalaSourceFactsCell>>,
    bulk_file_states: Option<Arc<HashMap<ProjectFile, ScalaFileFacts>>>,
    callable_alternatives_by_unit: Mutex<HashMap<CodeUnit, CallableAlternativesCell>>,
    effective_callable_alternatives_by_unit: Mutex<HashMap<CodeUnit, CallableAlternativesCell>>,
    extension_methods_by_owner_member:
        Mutex<HashMap<ExtensionOwnerMemberKey, ExtensionMethodEntries>>,
    override_targets_by_method: Mutex<HashMap<String, OverrideTargetEntries>>,
    exported_member_bindings_by_owner: Mutex<HashMap<String, Vec<(String, String)>>>,
}

/// Immutable Scala file facts plus the hierarchy layer resolved from them.
///
/// A relational frontier rebuilds [`ProjectTypes`] on every provisional pass
/// so none of its mutable memo cells can retain an empty provisional answer.
/// Keeping this seed in `Arc`s makes those rebuilds copy only handles. Once the
/// hierarchy frontier converges, [`Self::resolved_seed`] carries that layer to
/// every file-local frontier without asking the same workspace questions again.
#[derive(Clone)]
pub struct ScalaProjectTypesSeed {
    type_aliases: Arc<HashSet<CodeUnit>>,
    direct_ancestors_by_owner: Option<Arc<HashMap<String, Vec<CodeUnit>>>>,
    direct_ancestors_by_unit: Option<Arc<HashMap<CodeUnit, Vec<CodeUnit>>>>,
    ambiguous_direct_ancestor_owners: Option<Arc<HashSet<CodeUnit>>>,
    structural_parent_by_unit: Arc<HashMap<CodeUnit, CodeUnit>>,
    scala_trait_fqns: Arc<HashSet<String>>,
    bulk_file_states: Arc<HashMap<ProjectFile, ScalaFileFacts>>,
}

#[derive(Clone, Copy)]
enum ScalaCallMatch<'a> {
    Arities(Option<&'a [usize]>),
    Shape(&'a ScalaCallSiteShape),
}

impl ScalaCallMatch<'_> {
    fn is_unapplied(self) -> bool {
        match self {
            Self::Arities(call_arities) => call_arities.is_none(),
            Self::Shape(shape) => shape.lists.is_empty(),
        }
    }
}

fn sorted_unique_units(mut units: Vec<CodeUnit>) -> Vec<CodeUnit> {
    units.sort();
    units.dedup();
    units
}

/// True when `left` and `right` were one merged CodeUnit before Scala
/// overloads gained per-overload signature keys (#1327): identical on every
/// identity field except `signature`. Uniqueness gates that predate the split
/// mean "unique modulo signature", so they must treat a same-file overload
/// family as a single physical declaration and leave overload selection to the
/// call-shape machinery downstream.
pub fn same_overload_family(left: &CodeUnit, right: &CodeUnit) -> bool {
    left.source() == right.source()
        && left.kind() == right.kind()
        && left.package_name() == right.package_name()
        && left.short_name() == right.short_name()
        && left.is_synthetic() == right.is_synthetic()
}

/// True when every unit in the set belongs to one overload family (see
/// [`same_overload_family`]). Empty sets are vacuously a single family.
pub fn single_overload_family<'a>(mut units: impl Iterator<Item = &'a CodeUnit>) -> bool {
    let Some(first) = units.next() else {
        return true;
    };
    units.all(|unit| same_overload_family(first, unit))
}

/// True when `left` and `right` are two physical declarations of ONE logical
/// Scala symbol: same kind, same package, same short name, same synthetic
/// flag, differing only in which file declares them (#2021). This is
/// [`same_overload_family`] with the source conjunct removed, so
/// `single_overload_family(X)` implies `single_replica_family(X)` for every
/// set X.
///
/// Identity here is structural and nothing else. This predicate never reads a
/// terminal name segment, a rendered display string, or a file path, and no
/// caller may substitute such a comparison for it: replicas are merged on full
/// structured identity and explicit source ownership, never on name
/// similarity.
pub fn same_replica_family(left: &CodeUnit, right: &CodeUnit) -> bool {
    left.kind() == right.kind()
        && left.package_name() == right.package_name()
        && left.short_name() == right.short_name()
        && left.is_synthetic() == right.is_synthetic()
}

/// True when every unit in the set belongs to one replica family (see
/// [`same_replica_family`]). Empty sets are vacuously a single family, which
/// matches [`single_overload_family`]; callers that need "at least one" must
/// check emptiness themselves, and the existing gates do.
pub fn single_replica_family<'a>(mut units: impl Iterator<Item = &'a CodeUnit>) -> bool {
    let Some(first) = units.next() else {
        return true;
    };
    units.all(|unit| same_replica_family(first, unit))
}

impl ProjectTypes {
    /// The declarations a bulk file-state read contributes to Scala's
    /// request-local project facts, in insertion order. What stays here is the
    /// decision about *which* units enter, which is Scala's:
    /// the definition-lookup units and the declarations, file scopes excluded,
    /// deduplicated in that order.
    pub fn indexable_declarations(
        file_states: &HashMap<ProjectFile, ScalaFileFacts>,
    ) -> Vec<CodeUnit> {
        let mut declarations = Vec::new();
        let mut seen = HashSet::default();
        for state in file_states.values() {
            for unit in state
                .definition_lookup_units
                .iter()
                .chain(&state.declarations)
            {
                if !unit.is_file_scope() && seen.insert(unit.clone()) {
                    declarations.push(unit.clone());
                }
            }
        }
        declarations
    }

    /// Assemble the project type index from a bulk file-state read plus the two
    /// finished analysis-side indexes built over
    /// [`Self::indexable_declarations`].
    pub fn from_parts(
        index: Arc<dyn ScalaDefinitionIndex>,
        facts: Arc<dyn ScalaCallableFactsIndex>,
        file_states: HashMap<ProjectFile, ScalaFileFacts>,
    ) -> Self {
        Self::from_seed(index, facts, Self::seed(Arc::new(file_states)))
    }

    pub fn seed(file_states: Arc<HashMap<ProjectFile, ScalaFileFacts>>) -> ScalaProjectTypesSeed {
        let type_aliases = Arc::new(
            file_states
                .values()
                .flat_map(|state| state.type_aliases.iter().cloned())
                .collect(),
        );
        let structural_parent_by_unit = file_states
            .values()
            .flat_map(|state| {
                state.children.iter().flat_map(|(parent, children)| {
                    children
                        .iter()
                        .cloned()
                        .map(|child| (child, parent.clone()))
                })
            })
            .collect();
        let scala_trait_fqns = Arc::new(
            file_states
                .values()
                .flat_map(|state| state.scala_traits.iter().map(CodeUnit::fq_name))
                .collect(),
        );
        ScalaProjectTypesSeed {
            type_aliases,
            direct_ancestors_by_owner: None,
            direct_ancestors_by_unit: None,
            ambiguous_direct_ancestor_owners: None,
            structural_parent_by_unit: Arc::new(structural_parent_by_unit),
            scala_trait_fqns,
            bulk_file_states: file_states,
        }
    }

    pub fn from_seed(
        index: Arc<dyn ScalaDefinitionIndex>,
        facts: Arc<dyn ScalaCallableFactsIndex>,
        seed: ScalaProjectTypesSeed,
    ) -> Self {
        let mut types = Self {
            index,
            type_aliases: Arc::clone(&seed.type_aliases),
            facts,
            direct_ancestors_by_owner: seed.direct_ancestors_by_owner.clone(),
            direct_ancestors_by_unit: seed.direct_ancestors_by_unit.clone(),
            ambiguous_direct_ancestor_owners: seed.ambiguous_direct_ancestor_owners.clone(),
            structural_parent_by_unit: Some(Arc::clone(&seed.structural_parent_by_unit)),
            scala_trait_fqns: Some(Arc::clone(&seed.scala_trait_fqns)),
            package_types_by_package: Mutex::new(HashMap::default()),
            package_objects_by_package: Mutex::new(HashMap::default()),
            nested_types_by_owner: Mutex::new(HashMap::default()),
            nested_objects_by_owner: Mutex::new(HashMap::default()),
            wildcard_members_by_owner: Mutex::new(HashMap::default()),
            source_facts_by_file: Mutex::new(HashMap::default()),
            bulk_file_states: Some(Arc::clone(&seed.bulk_file_states)),
            callable_alternatives_by_unit: Mutex::new(HashMap::default()),
            effective_callable_alternatives_by_unit: Mutex::new(HashMap::default()),
            extension_methods_by_owner_member: Mutex::new(HashMap::default()),
            override_targets_by_method: Mutex::new(HashMap::default()),
            exported_member_bindings_by_owner: Mutex::new(HashMap::default()),
        };
        if types.direct_ancestors_by_unit.is_some() {
            debug_assert!(types.direct_ancestors_by_owner.is_some());
            debug_assert!(types.ambiguous_direct_ancestor_owners.is_some());
            return types;
        }
        let (direct_ancestors_by_unit, ambiguous_direct_ancestor_owners) = types
            .resolve_direct_ancestors_from_file_states(
                types
                    .bulk_file_states
                    .as_ref()
                    .expect("bulk Scala file states were just installed"),
            );
        let direct_ancestors_by_owner = direct_ancestors_by_unit
            .iter()
            .map(|(owner, ancestors)| (owner.fq_name(), ancestors.clone()))
            .collect();
        types.direct_ancestors_by_owner = Some(Arc::new(direct_ancestors_by_owner));
        types.direct_ancestors_by_unit = Some(Arc::new(direct_ancestors_by_unit));
        types.ambiguous_direct_ancestor_owners = Some(Arc::new(ambiguous_direct_ancestor_owners));
        types
    }

    pub fn resolved_seed(&self) -> ScalaProjectTypesSeed {
        ScalaProjectTypesSeed {
            type_aliases: Arc::clone(&self.type_aliases),
            direct_ancestors_by_owner: Some(Arc::clone(
                self.direct_ancestors_by_owner
                    .as_ref()
                    .expect("Scala project hierarchy is initialized"),
            )),
            direct_ancestors_by_unit: Some(Arc::clone(
                self.direct_ancestors_by_unit
                    .as_ref()
                    .expect("Scala project hierarchy is initialized"),
            )),
            ambiguous_direct_ancestor_owners: Some(Arc::clone(
                self.ambiguous_direct_ancestor_owners
                    .as_ref()
                    .expect("Scala project hierarchy is initialized"),
            )),
            structural_parent_by_unit: Arc::clone(
                self.structural_parent_by_unit
                    .as_ref()
                    .expect("Scala structural parents are initialized"),
            ),
            scala_trait_fqns: Arc::clone(
                self.scala_trait_fqns
                    .as_ref()
                    .expect("Scala trait facts are initialized"),
            ),
            bulk_file_states: Arc::clone(
                self.bulk_file_states
                    .as_ref()
                    .expect("Scala bulk file facts are initialized"),
            ),
        }
    }

    pub fn exact_direct_ancestors_snapshot(&self) -> Option<&HashMap<CodeUnit, Vec<CodeUnit>>> {
        self.direct_ancestors_by_unit.as_deref()
    }

    pub fn definitions_by_fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        self.index.by_fqn(fqn)
    }

    pub fn definitions_by_normalized_fqn(&self, normalized: &str) -> Vec<CodeUnit> {
        self.index.by_normalized_fqn(normalized)
    }

    /// Resolve one definition name with the same exact-first precedence as
    /// [`CodeUnitIndex::definitions`], but through the request's relational
    /// definition surface.
    pub fn definitions(&self, fqn: &str) -> Vec<CodeUnit> {
        let exact = self.definitions_by_fqn(fqn);
        if !exact.is_empty() {
            return exact;
        }
        self.definitions_by_normalized_fqn(&scala_normalized_fq_name(fqn))
    }

    pub fn exact_direct_ancestors(&self, owner: &CodeUnit) -> Vec<CodeUnit> {
        self.direct_ancestors_by_unit
            .as_ref()
            .expect("Scala project hierarchy is initialized")
            .get(owner)
            .cloned()
            .unwrap_or_default()
    }

    pub fn projected_structural_parent(&self, unit: &CodeUnit) -> Option<CodeUnit> {
        self.structural_parent_by_unit
            .as_ref()
            .expect("Scala structural parents are initialized")
            .get(unit)
            .cloned()
    }

    pub fn exact_ancestors(&self, owner: &CodeUnit) -> Vec<CodeUnit> {
        let mut pending = self.exact_direct_ancestors(owner);
        let mut seen = HashSet::default();
        while let Some(current) = pending.pop() {
            if seen.insert(current.clone()) {
                pending.extend(self.exact_direct_ancestors(&current));
            }
        }
        let mut ancestors = seen.into_iter().collect::<Vec<_>>();
        ancestors.sort();
        ancestors
    }

    pub fn exact_descendants(&self, owner: &CodeUnit) -> Vec<CodeUnit> {
        let ancestors_by_unit = self
            .direct_ancestors_by_unit
            .as_ref()
            .expect("Scala project hierarchy is initialized");
        let mut direct = HashMap::<CodeUnit, Vec<CodeUnit>>::default();
        for (candidate, ancestors) in ancestors_by_unit.iter() {
            for ancestor in ancestors {
                direct
                    .entry(ancestor.clone())
                    .or_default()
                    .push(candidate.clone());
            }
        }
        let mut pending = direct.remove(owner).unwrap_or_default();
        let mut seen = HashSet::default();
        while let Some(current) = pending.pop() {
            if seen.insert(current.clone())
                && let Some(children) = direct.get(&current)
            {
                pending.extend(children.iter().cloned());
            }
        }
        let mut descendants = seen.into_iter().collect::<Vec<_>>();
        descendants.sort();
        descendants
    }

    pub fn bulk_file_state(&self, file: &ProjectFile) -> Option<&ScalaFileFacts> {
        self.bulk_file_states.as_ref()?.get(file)
    }

    fn callable_facts(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        declaration: &CodeUnit,
    ) -> Option<CallableFacts> {
        if !declaration.is_function() && !declaration.is_field() {
            return None;
        }
        let fact = self
            .facts
            .facts_for_declaration(declaration)
            .into_iter()
            .filter(|fact| fact.declaration == *declaration)
            .min_by_key(|fact| fact.signature_ordinal);
        let signature = fact
            .as_ref()
            .map(|fact| fact.signature.as_str())
            .or_else(|| declaration.signature());
        let metadata = fact.as_ref().and_then(|fact| fact.metadata.as_ref());
        let return_type_fqn = metadata
            .and_then(SignatureMetadata::return_type_identity)
            .and_then(|identity| identity.nominal_name())
            .and_then(|name| {
                let resolver = NameResolver::for_file_types(scala, token, declaration, self);
                self.resolve_type_in_callable_declaration_context(
                    scala,
                    &resolver,
                    declaration,
                    name.path(),
                )
            });
        Some(CallableFacts {
            arity: signature.and_then(scala_member_signature_arity),
            callable_arity: metadata.and_then(SignatureMetadata::callable_arity),
            return_type_fqn,
            is_function: declaration.is_function(),
        })
    }

    fn is_type_alias(&self, _scala: &dyn ScalaSource, unit: &CodeUnit) -> bool {
        self.type_aliases.contains(unit)
    }

    /// Whether this field-shaped declaration identity also has a term-level
    /// declaration. Scala permits a type alias and a `val` with the same name
    /// in one owner; the analyzer intentionally coalesces those declarations
    /// into one CodeUnit while retaining both parser-recorded signatures.
    pub fn has_term_field_declaration(&self, unit: &CodeUnit) -> bool {
        unit.is_field()
            && (!self.type_aliases.contains(unit)
                || self
                    .bulk_file_state(unit.source())
                    .and_then(|state| state.signatures.get(unit))
                    .is_some_and(|signatures| signatures.len() > 1))
    }

    fn is_exclusive_type_alias(&self, unit: &CodeUnit) -> bool {
        self.type_aliases.contains(unit) && !self.has_term_field_declaration(unit)
    }

    fn term_field_declaration_is_globally_unique(&self, unit: &CodeUnit) -> bool {
        self.index
            .by_fqn(&unit.fq_name())
            .iter()
            .filter(|candidate| self.has_term_field_declaration(candidate))
            .count()
            == 1
    }

    fn is_type_namespace_declaration(&self, unit: &CodeUnit) -> bool {
        unit.is_class() || self.type_aliases.contains(unit)
    }

    /// Where `unit` ranks in the type namespace. A declared `object` reaches the
    /// type namespace only as `O.type`, so it ranks below every class, trait,
    /// and type alias of the same name whatever the lexical precedence of the
    /// two declarations.
    fn type_namespace_tier(&self, unit: &CodeUnit) -> u8 {
        if unit.short_name().ends_with('$') && !self.type_aliases.contains(unit) {
            OBJECT_TYPE_NAMESPACE_TIER
        } else {
            NAMESPACE_TIER
        }
    }

    fn is_exact_structural_child(
        &self,
        scala: &dyn ScalaSource,
        owner: &CodeUnit,
        unit: &CodeUnit,
    ) -> bool {
        match &self.structural_parent_by_unit {
            Some(parents) => parents.get(unit) == Some(owner),
            None => scala.structural_parent_of(unit).as_ref() == Some(owner),
        }
    }

    fn exact_structural_parent(
        &self,
        scala: &dyn ScalaSource,
        unit: &CodeUnit,
    ) -> Option<CodeUnit> {
        match &self.structural_parent_by_unit {
            Some(parents) => parents.get(unit).cloned(),
            None => scala.structural_parent_of(unit),
        }
    }

    fn declaration_parent(&self, scala: &dyn ScalaSource, unit: &CodeUnit) -> Option<CodeUnit> {
        match &self.structural_parent_by_unit {
            Some(parents) => parents.get(unit).cloned(),
            None => scala
                .structural_parent_of(unit)
                .or_else(|| scala.parent_of(unit)),
        }
    }

    pub fn exact_type_declaration_for_owner_context(
        &self,
        fqn: &str,
        owner: &CodeUnit,
    ) -> ScalaTypeNamespaceResolution {
        let candidates = sorted_unique_units(
            self.index
                .by_fqn(fqn)
                .iter()
                .filter(|unit| unit.is_class() && unit.fq_name() == fqn)
                .cloned()
                .collect::<Vec<_>>(),
        );
        let same_source = candidates
            .iter()
            .filter(|unit| unit.source() == owner.source())
            .cloned()
            .collect::<Vec<_>>();
        match same_source.as_slice() {
            [definition] => {
                return ScalaTypeNamespaceResolution::Resolved((*definition).clone());
            }
            [_, _, ..] => return ScalaTypeNamespaceResolution::Ambiguous(same_source),
            [] => {}
        }
        match candidates.as_slice() {
            [] => ScalaTypeNamespaceResolution::NoMatch,
            [definition] => ScalaTypeNamespaceResolution::Resolved((*definition).clone()),
            _ => ScalaTypeNamespaceResolution::Ambiguous(candidates),
        }
    }

    fn exact_type_declarations_for_owner_context(
        &self,
        fqn: &str,
        owner: &CodeUnit,
    ) -> Vec<CodeUnit> {
        let candidates = sorted_unique_units(
            self.index
                .by_fqn(fqn)
                .iter()
                .filter(|unit| unit.is_class() && unit.fq_name() == fqn)
                .cloned()
                .collect::<Vec<_>>(),
        );
        let same_source = candidates
            .iter()
            .filter(|unit| unit.source() == owner.source())
            .cloned()
            .collect::<Vec<_>>();
        if same_source.is_empty() {
            candidates
        } else {
            sorted_unique_units(same_source)
        }
    }

    fn export_infos_for_owner(
        &self,
        scala: &dyn ScalaSource,
        owner: &CodeUnit,
    ) -> Vec<ScalaExportInfo> {
        match &self.bulk_file_states {
            Some(states) => states
                .get(owner.source())
                .and_then(|state| state.scala_exports.get(owner))
                .cloned()
                .unwrap_or_default(),
            None => scala.export_infos_for_owner(owner),
        }
    }

    fn imports_for_export_owner(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        owner: &CodeUnit,
    ) -> Vec<ImportInfo> {
        match &self.bulk_file_states {
            Some(states) => states
                .get(owner.source())
                .map(|state| state.imports.clone())
                .unwrap_or_default(),
            None => scala.import_info_of(token, owner.source()),
        }
    }

    fn physical_callable_targets(
        &self,
        scala: &dyn ScalaSource,
        targets: Vec<CodeUnit>,
    ) -> PhysicalCallableTargets {
        if targets.is_empty() {
            return PhysicalCallableTargets::NoCandidates;
        }
        let owners = targets
            .iter()
            .filter_map(|target| self.exact_structural_parent(scala, target))
            .collect::<HashSet<_>>();
        // Cross-built replicas of one owner are distinct CodeUnit values,
        // because their sources differ, so a raw owner count reads a coherent
        // replica family as an ambiguity and drops the application (#2021). A
        // replica family is one logical owner with several physical homes and
        // contributes every member's callable, exactly as a same-file overload
        // family does. Owners that disagree on an identity field are a genuine
        // collision and stay ambiguous.
        if owners.len() > 1 && !single_replica_family(owners.iter()) {
            PhysicalCallableTargets::Ambiguous
        } else {
            PhysicalCallableTargets::Unique(targets)
        }
    }

    fn fallback_callable_role(
        &self,
        scala: &dyn ScalaSource,
        unit: &CodeUnit,
    ) -> ScalaCallableRole {
        if unit.is_synthetic() {
            ScalaCallableRole::PrimaryConstructor
        } else if self
            .exact_structural_parent(scala, unit)
            .is_some_and(|owner| owner.identifier().trim_end_matches('$') == unit.identifier())
        {
            ScalaCallableRole::SecondaryConstructor
        } else {
            ScalaCallableRole::Ordinary
        }
    }

    fn direct_member_bindings(&self, owner_fqn: &str) -> ExportedMemberBindings {
        let mut bindings = ExportedMemberBindings::default();
        for child in self.index.fqn_direct_children(owner_fqn) {
            if child.is_function() || child.is_field() || self.type_aliases.contains(&child) {
                let visible_name = scala_short_name_terminal_segment(child.short_name());
                bindings
                    .entry(visible_name)
                    .or_default()
                    .insert(child.fq_name());
            }
        }
        bindings
    }

    /// Resolve the original declarations exposed as members of `exporter`.
    ///
    /// Export aliases are compiler-generated declarations and therefore do
    /// not appear in the source declaration index. Build their bindings from
    /// parser-recorded export facts instead. Discovery is iterative and the
    /// propagation is a finite monotonic fixed point, so malformed export
    /// cycles terminate without losing valid aliases on another path.
    pub fn exported_member_bindings(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        exporter: &CodeUnit,
    ) -> Vec<(String, String)> {
        let exporter_fqn = exporter.fq_name();
        if let Some(cached) = self
            .exported_member_bindings_by_owner
            .lock()
            .expect("Scala export binding cache poisoned")
            .get(&exporter_fqn)
            .cloned()
        {
            return cached;
        }

        let mut queue = vec![exporter.clone()];
        let mut visited = HashSet::default();
        let mut owners = HashMap::<String, CodeUnit>::default();
        let mut edges = Vec::new();
        while let Some(current) = queue.pop() {
            let current_fqn = current.fq_name();
            if !visited.insert(current_fqn.clone()) {
                continue;
            }
            owners.insert(current_fqn.clone(), current.clone());
            let imports = self.imports_for_export_owner(scala, token, &current);
            for export in self.export_infos_for_owner(scala, &current) {
                if export.owner_path.is_empty() {
                    continue;
                }
                // Export qualifier paths are elaborated before aliases in the
                // same owner. Excluding member bindings here enforces that
                // path-before-alias rule while retaining ordinary import and
                // package precedence.
                let visible_imports =
                    visible_imports_at_byte(&imports, Some(export.declaration_start_byte));
                let resolver = NameResolver::for_file_with_facts_impl(
                    scala,
                    token,
                    Some(current.source()),
                    &[current.package_name().to_string()],
                    &visible_imports,
                    self,
                    false,
                    &HashMap::default(),
                );
                let lexical_root = export
                    .owner_path
                    .first()
                    .and_then(|root| self.exact_nested_object_for_owner(scala, &current, root));
                let Some(source_owner_fqn) = self.resolve_qualified_stable_type_at(
                    scala,
                    &resolver,
                    &export.owner_path,
                    true,
                    lexical_root,
                ) else {
                    continue;
                };
                let normalized = scala_normalized_fq_name(&source_owner_fqn);
                let Some(source_owner) = self.object_by_normalized_fqn(scala, &normalized) else {
                    continue;
                };
                let source_owner_fqn = source_owner.fq_name();
                edges.push(ScalaExportEdge {
                    exporter_fqn: current_fqn.clone(),
                    source_owner_fqn: source_owner_fqn.clone(),
                    selectors: export.selectors,
                });
                if !visited.contains(&source_owner_fqn) {
                    queue.push(source_owner);
                }
            }
        }

        let mut bindings_by_owner = owners
            .keys()
            .map(|owner_fqn| (owner_fqn.clone(), self.direct_member_bindings(owner_fqn)))
            .collect::<HashMap<_, _>>();
        loop {
            let mut changed = false;
            for edge in &edges {
                let Some(source_bindings) = bindings_by_owner.get(&edge.source_owner_fqn).cloned()
                else {
                    continue;
                };
                let destination = bindings_by_owner
                    .entry(edge.exporter_fqn.clone())
                    .or_default();
                let named_sources = edge
                    .selectors
                    .iter()
                    .filter_map(|selector| match selector {
                        ScalaExportSelector::Named { source_name, .. } => Some(source_name.clone()),
                        ScalaExportSelector::Wildcard | ScalaExportSelector::GivenWildcard => None,
                    })
                    .collect::<HashSet<_>>();
                for selector in &edge.selectors {
                    match selector {
                        ScalaExportSelector::Named {
                            source_name,
                            visible_name,
                        } => {
                            let Some(visible_name) = visible_name else {
                                continue;
                            };
                            let Some(candidates) = source_bindings.get(source_name) else {
                                continue;
                            };
                            let target = destination.entry(visible_name.clone()).or_default();
                            let previous = target.len();
                            target.extend(candidates.iter().cloned());
                            changed |= target.len() != previous;
                        }
                        ScalaExportSelector::Wildcard => {
                            for (visible_name, candidates) in &source_bindings {
                                if named_sources.contains(visible_name) {
                                    continue;
                                }
                                let target = destination.entry(visible_name.clone()).or_default();
                                let previous = target.len();
                                target.extend(candidates.iter().cloned());
                                changed |= target.len() != previous;
                            }
                        }
                        // Given exports have distinct eligibility rules. Do
                        // not expose them as ordinary term-member bindings.
                        ScalaExportSelector::GivenWildcard => {}
                    }
                }
            }
            if !changed {
                break;
            }
        }

        let flattened_by_owner = bindings_by_owner
            .into_iter()
            .map(|(owner_fqn, bindings)| {
                let mut flattened = bindings
                    .into_iter()
                    .flat_map(|(visible_name, candidates)| {
                        candidates
                            .into_iter()
                            .map(move |candidate| (visible_name.clone(), candidate))
                    })
                    .collect::<Vec<_>>();
                flattened.sort();
                flattened.dedup();
                (owner_fqn, flattened)
            })
            .collect::<Vec<_>>();
        let result = flattened_by_owner
            .iter()
            .find(|(owner_fqn, _)| owner_fqn == &exporter_fqn)
            .map(|(_, bindings)| bindings.clone())
            .unwrap_or_default();
        let mut cache = self
            .exported_member_bindings_by_owner
            .lock()
            .expect("Scala export binding cache poisoned");
        for (owner_fqn, bindings) in flattened_by_owner {
            cache.entry(owner_fqn).or_insert(bindings);
        }
        result
    }

    pub fn resolve_direct_ancestors_from_file_states(
        &self,
        file_states: &HashMap<ProjectFile, ScalaFileFacts>,
    ) -> (HashMap<CodeUnit, Vec<CodeUnit>>, HashSet<CodeUnit>) {
        let mut ancestors_by_owner = HashMap::default();
        let mut ambiguous_owners = HashSet::default();
        let projected_parent_by_unit = file_states
            .values()
            .flat_map(|state| {
                state.children.iter().flat_map(|(parent, children)| {
                    children
                        .iter()
                        .cloned()
                        .map(|child| (child, parent.clone()))
                })
            })
            .collect::<HashMap<_, _>>();
        for (file, state) in file_states {
            if state.supertype_lookup_paths.is_empty() {
                continue;
            }
            let lookup_paths_by_owner = state
                .supertype_lookup_paths
                .iter()
                .filter_map(|(owner, encoded)| {
                    let paths = encoded
                        .iter()
                        .map(|path| ScalaSupertypeLookupPath::decode(path))
                        .collect::<Option<Vec<_>>>()?;
                    Some((owner.clone(), paths))
                })
                .collect::<HashMap<_, _>>();
            let mut required_names_by_package = HashMap::<String, HashSet<String>>::default();
            for (owner, paths) in &lookup_paths_by_owner {
                required_names_by_package
                    .entry(owner.package_name().to_string())
                    .or_default()
                    .extend(
                        paths
                            .iter()
                            .filter_map(|path| path.segments().first().cloned()),
                    );
            }
            let resolvers_by_package = required_names_by_package
                .into_iter()
                .map(|(package, required_names)| {
                    let resolver = NameResolver::for_type_hierarchy_file(
                        Some(file),
                        Some(&package),
                        &state.imports,
                        self,
                        &required_names,
                    );
                    (package, resolver)
                })
                .collect::<HashMap<_, _>>();
            let parent_by_child = state
                .children
                .iter()
                .flat_map(|(parent, children)| children.iter().map(move |child| (child, parent)))
                .collect::<HashMap<_, _>>();
            for (owner, lookup_paths) in lookup_paths_by_owner {
                if !owner.is_class() {
                    continue;
                }
                let Some(resolver) = resolvers_by_package.get(owner.package_name()) else {
                    continue;
                };
                let mut ancestors = Vec::new();
                let mut seen = HashSet::default();
                for path in lookup_paths {
                    let Some(fqn) = self.resolve_type_in_owner_context(
                        resolver,
                        path.segments(),
                        &owner,
                        state,
                        &parent_by_child,
                        &projected_parent_by_unit,
                    ) else {
                        if self.type_lookup_path_is_ambiguous(resolver, path.segments()) {
                            ambiguous_owners.insert(owner.clone());
                            ancestors.clear();
                            break;
                        }
                        continue;
                    };
                    if !seen.insert(fqn.clone()) {
                        continue;
                    }
                    ancestors.extend(self.exact_type_declarations_for_owner_context(&fqn, &owner));
                }
                if !ancestors.is_empty() {
                    ancestors_by_owner.insert(owner.clone(), ancestors);
                }
            }
        }
        (ancestors_by_owner, ambiguous_owners)
    }

    pub fn direct_ancestors_for_owner(
        &self,
        _scala: &dyn ScalaSource,
        owner_fqn: &str,
    ) -> Vec<CodeUnit> {
        self.direct_ancestors_by_owner
            .as_ref()
            .expect("Scala project hierarchy is initialized")
            .get(owner_fqn)
            .cloned()
            .unwrap_or_default()
    }

    fn direct_ancestors_for_declaration(
        &self,
        _scala: &dyn ScalaSource,
        owner: &CodeUnit,
    ) -> Vec<CodeUnit> {
        self.exact_direct_ancestors(owner)
    }

    pub fn exact_owner_inherits(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        owner: &CodeUnit,
        target: &CodeUnit,
    ) -> bool {
        let mut pending = vec![owner.clone()];
        let mut seen = HashSet::default();
        while let Some(current) = pending.pop() {
            if !seen.insert(current.clone()) {
                continue;
            }
            if &current == target {
                return true;
            }
            let ancestors = match self.exact_direct_ancestor_resolution(scala, token, &current) {
                ScalaDirectAncestorResolution::Resolved(ancestors)
                | ScalaDirectAncestorResolution::Incomplete(ancestors)
                    if !ancestors.is_empty() =>
                {
                    ancestors
                }
                ScalaDirectAncestorResolution::Resolved(_)
                | ScalaDirectAncestorResolution::Incomplete(_) => {
                    self.direct_ancestors_for_declaration(scala, &current)
                }
                ScalaDirectAncestorResolution::Ambiguous => return false,
            };
            pending.extend(ancestors);
        }
        false
    }

    pub fn exact_direct_ancestor_resolution(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        owner: &CodeUnit,
    ) -> ScalaDirectAncestorResolution {
        if self
            .ambiguous_direct_ancestor_owners
            .as_ref()
            .is_some_and(|owners| owners.contains(owner))
        {
            return ScalaDirectAncestorResolution::Ambiguous;
        }
        if let Some(ancestors_by_unit) = &self.direct_ancestors_by_unit {
            return ScalaDirectAncestorResolution::Resolved(
                ancestors_by_unit.get(owner).cloned().unwrap_or_default(),
            );
        }

        let Some(facts) = scala.forward_owner_facts(owner) else {
            return ScalaDirectAncestorResolution::Resolved(Vec::new());
        };
        let resolver = NameResolver::for_file_types(scala, token, owner, self);
        let mut ancestors = Vec::new();
        let mut seen = HashSet::default();
        for path in facts.supertype_lookup_paths {
            let Some(fqn) =
                self.resolve_type_in_hierarchy_context(scala, &resolver, path.segments())
            else {
                if self.type_lookup_path_is_ambiguous(&resolver, path.segments()) {
                    return ScalaDirectAncestorResolution::Ambiguous;
                }
                continue;
            };
            for declaration in self.exact_type_declarations_for_owner_context(&fqn, owner) {
                if seen.insert(declaration.clone()) {
                    ancestors.push(declaration);
                }
            }
        }
        ScalaDirectAncestorResolution::Resolved(ancestors)
    }

    pub fn exact_lexical_type_namespace(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        owners_nearest_first: impl IntoIterator<Item = CodeUnit>,
        name: &str,
        authoritative_local_barrier: bool,
    ) -> ScalaTypeNamespaceResolution {
        resolve_exact_lexical_type_namespace(
            owners_nearest_first,
            name,
            authoritative_local_barrier,
            |owner, member| {
                self.members_for_exact_owner_unit(scala, owner, member)
                    .into_iter()
                    .filter(|unit| {
                        unit.is_class() && !unit.short_name().ends_with('$')
                            || self.is_type_alias(scala, unit)
                    })
                    .collect()
            },
            |owner| self.exact_direct_ancestor_resolution(scala, token, owner),
        )
    }

    fn direct_field_ancestors_for_owner(
        &self,
        _scala: &dyn ScalaSource,
        owner_fqn: &str,
    ) -> Vec<CodeUnit> {
        self.direct_ancestors_by_owner
            .as_ref()
            .expect("Scala project hierarchy is initialized")
            .get(owner_fqn)
            .cloned()
            .unwrap_or_default()
    }

    pub fn field_for_owner_member(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        owner_fqn: &str,
        member: &str,
    ) -> FieldResolution {
        let mut level = vec![owner_fqn.to_string()];
        let mut seen = HashSet::default();
        while !level.is_empty() {
            let mut matches = Vec::new();
            let mut next = Vec::new();
            for owner in level {
                if !seen.insert(owner.clone()) {
                    continue;
                }
                matches.extend(
                    self.members_for_exact_owner_name(&owner, member)
                        .into_iter()
                        .filter(|unit| self.has_term_field_declaration(unit)),
                );
                next.extend(
                    self.direct_field_ancestors_for_owner(scala, &owner)
                        .into_iter()
                        .map(|ancestor| ancestor.fq_name()),
                );
            }
            if !matches.is_empty() {
                let mut unique = HashSet::default();
                matches.retain(|field| unique.insert(field.clone()));
                if matches.len() != 1 {
                    return FieldResolution::Unresolved;
                }
                let declaration = matches.pop().expect("one exact Scala field");
                let declared_type = self.field_declared_type(scala, token, &declaration);
                return FieldResolution::Resolved(ResolvedField {
                    declaration,
                    declared_type,
                });
            }
            level = next;
        }
        FieldResolution::NoMatch
    }

    pub fn field_for_owner_unit(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        owner: &CodeUnit,
        member: &str,
    ) -> FieldResolution {
        let mut level = vec![owner.clone()];
        let mut seen = HashSet::default();
        while !level.is_empty() {
            let mut matches = Vec::new();
            let mut next = Vec::new();
            for owner in level {
                if !seen.insert(owner.clone()) {
                    continue;
                }
                matches.extend(
                    self.members_for_exact_owner_unit(scala, &owner, member)
                        .into_iter()
                        .filter(|unit| self.has_term_field_declaration(unit)),
                );
                let ancestors = match self.exact_direct_ancestor_resolution(scala, token, &owner) {
                    ScalaDirectAncestorResolution::Resolved(ancestors)
                    | ScalaDirectAncestorResolution::Incomplete(ancestors)
                        if !ancestors.is_empty() =>
                    {
                        ancestors
                    }
                    ScalaDirectAncestorResolution::Resolved(_)
                    | ScalaDirectAncestorResolution::Incomplete(_) => {
                        // The forward hierarchy resolver deliberately fails closed on
                        // ambiguity, but its bounded fallback cannot currently recover
                        // every nested lexical supertype. The analyzer hierarchy retains
                        // exact CodeUnits for that case, so use it only after the exact
                        // resolver has authoritatively ruled out ambiguity.
                        self.direct_ancestors_for_declaration(scala, &owner)
                    }
                    ScalaDirectAncestorResolution::Ambiguous => {
                        return FieldResolution::Unresolved;
                    }
                };
                next.extend(ancestors);
            }
            matches.sort();
            matches.dedup();
            match matches.as_slice() {
                [field] => {
                    return FieldResolution::Resolved(ResolvedField {
                        declaration: field.clone(),
                        declared_type: self.field_declared_type(scala, token, field),
                    });
                }
                [_, _, ..] => return FieldResolution::Unresolved,
                [] => level = next,
            }
        }
        FieldResolution::NoMatch
    }

    pub fn stable_type_member_for_owner_unit(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        owner: &CodeUnit,
        member: &str,
    ) -> FieldResolution {
        let mut level = vec![owner.clone()];
        let mut seen = HashSet::default();
        while !level.is_empty() {
            let mut matches = Vec::new();
            let mut next = Vec::new();
            let mut next_is_ambiguous = false;
            let mut level_owners = Vec::new();
            for owner in level {
                if !seen.insert(owner.clone()) {
                    continue;
                }
                level_owners.push(owner.clone());
                matches.extend(
                    self.members_for_exact_owner_unit(scala, &owner, member)
                        .into_iter()
                        .filter(|unit| unit.is_field() || self.is_type_alias(scala, unit)),
                );
            }
            // A declaration directly owned at this hierarchy tier is
            // authoritative. Only consult exports and ancestors when the
            // complete direct tier has no matching declaration; otherwise an
            // unrelated ambiguous replica beyond that tier can incorrectly
            // hide the exact physical member.
            if matches.is_empty() {
                for owner in level_owners {
                    // Export aliases do not have a declaration under the exporter.
                    // Consult parser-recorded export bindings only for a physically
                    // unique exporter and require one physical target for every
                    // selected binding.
                    let exported_bindings = self
                        .exported_member_bindings(scala, token, &owner)
                        .into_iter()
                        .filter(|(visible_name, _)| visible_name == member)
                        .collect::<Vec<_>>();
                    if !exported_bindings.is_empty() {
                        let owner_declarations = self.index.by_fqn(&owner.fq_name());
                        let physical_owners = owner_declarations
                            .iter()
                            .filter(|candidate| candidate.is_class())
                            .collect::<Vec<_>>();
                        if physical_owners.len() != 1 || physical_owners[0] != &owner {
                            return FieldResolution::Unresolved;
                        }
                    }
                    for (_, target_fqn) in exported_bindings {
                        let target_declarations = self.index.by_fqn(&target_fqn);
                        let exported = target_declarations
                            .iter()
                            .filter(|candidate| {
                                candidate.is_field() || self.is_type_alias(scala, candidate)
                            })
                            .collect::<Vec<_>>();
                        let [exported] = exported.as_slice() else {
                            return FieldResolution::Unresolved;
                        };
                        matches.push((*exported).clone());
                    }
                    let ancestors =
                        match self.exact_direct_ancestor_resolution(scala, token, &owner) {
                            ScalaDirectAncestorResolution::Resolved(ancestors)
                            | ScalaDirectAncestorResolution::Incomplete(ancestors) => ancestors,
                            ScalaDirectAncestorResolution::Ambiguous => {
                                next_is_ambiguous = true;
                                Vec::new()
                            }
                        };
                    next.extend(ancestors);
                }
            }
            if !matches.is_empty() {
                let type_members = matches
                    .iter()
                    .filter(|field| self.is_type_alias(scala, field))
                    .cloned()
                    .collect::<Vec<_>>();
                if !type_members.is_empty() {
                    matches = type_members;
                }
                let mut unique = HashSet::default();
                matches.retain(|field| unique.insert(field.clone()));
                if matches.len() != 1 {
                    return FieldResolution::Unresolved;
                }
                return FieldResolution::Resolved(ResolvedField {
                    declaration: matches.pop().expect("one exact Scala stable type member"),
                    declared_type: None,
                });
            }
            if next_is_ambiguous {
                return FieldResolution::Unresolved;
            }
            level = next;
        }
        FieldResolution::NoMatch
    }

    fn field_declared_type(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        declaration: &CodeUnit,
    ) -> Option<String> {
        let source_facts = self.source_facts_for_file(scala, declaration.source());
        let resolver = NameResolver::for_file_types(scala, token, declaration, self);
        let mut resolved = HashSet::default();
        for range in self.declaration_ranges_for(scala, declaration) {
            if let Some(path) = source_facts
                .field_type_paths_by_range
                .get(&(range.start_byte, range.end_byte))
                && let Some(field_type) =
                    self.resolve_type_in_declaration_context(scala, &resolver, path)
                && let Some(field_type) = self.canonical_receiver_type(scala, token, &field_type)
            {
                resolved.insert(field_type);
            }
        }
        match resolved.len() {
            1 => return resolved.into_iter().next(),
            2.. => return None,
            0 => {}
        }
        self.callable_facts(scala, token, declaration)
            .and_then(|facts| facts.return_type_fqn)
            .and_then(|field_type| self.canonical_receiver_type(scala, token, &field_type))
    }

    fn canonical_receiver_type(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        receiver_type: &str,
    ) -> Option<String> {
        let mut current = receiver_type.to_string();
        let mut seen = HashSet::default();
        while seen.insert(current.clone()) {
            let declarations = self.index.by_fqn(&current);
            let aliases = declarations
                .iter()
                .filter(|unit| self.is_type_alias(scala, unit))
                .collect::<Vec<_>>();
            if aliases.is_empty() {
                return Some(current);
            }
            if declarations
                .iter()
                .any(|unit| unit.is_class() && !self.is_type_alias(scala, unit))
            {
                return None;
            }
            let underlying = aliases
                .into_iter()
                .filter_map(|alias| self.type_alias_underlying_type(scala, token, alias))
                .collect::<HashSet<_>>();
            if underlying.len() != 1 {
                return None;
            }
            current = underlying.into_iter().next().expect("one alias target");
        }
        None
    }

    fn type_alias_underlying_type(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        alias: &CodeUnit,
    ) -> Option<String> {
        let source_facts = self.source_facts_for_file(scala, alias.source());
        let resolver = NameResolver::for_file_types(scala, token, alias, self);
        let resolved = self
            .declaration_ranges_for(scala, alias)
            .into_iter()
            .filter_map(|range| {
                source_facts
                    .type_alias_paths_by_range
                    .get(&(range.start_byte, range.end_byte))
                    .and_then(|path| {
                        self.resolve_type_in_declaration_context(scala, &resolver, path)
                    })
            })
            .collect::<HashSet<_>>();
        (resolved.len() == 1)
            .then(|| resolved.into_iter().next())
            .flatten()
    }

    pub fn is_scala_trait_declaration(
        &self,
        scala: &dyn ScalaSource,
        code_unit: &CodeUnit,
    ) -> bool {
        if let Some(traits) = &self.scala_trait_fqns {
            return traits.contains(&code_unit.fq_name());
        }
        scala.is_scala_trait_declaration(code_unit)
    }

    fn method_declarations_for_members<T: Borrow<CodeUnit>>(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        members: &[T],
        call_arities: Option<&[usize]>,
    ) -> Vec<CodeUnit> {
        self.method_declarations_for_members_matching(
            scala,
            token,
            members,
            ScalaCallMatch::Arities(call_arities),
            ScalaCallableSiteRole::Ordinary,
        )
    }

    fn method_declarations_for_members_with_shape<T: Borrow<CodeUnit>>(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        members: &[T],
        call_shape: &ScalaCallSiteShape,
    ) -> Vec<CodeUnit> {
        self.method_declarations_for_members_matching(
            scala,
            token,
            members,
            ScalaCallMatch::Shape(call_shape),
            ScalaCallableSiteRole::Ordinary,
        )
    }

    fn callable_declarations_for_members_with_shape<T: Borrow<CodeUnit>>(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        members: &[T],
        call_shape: &ScalaCallSiteShape,
        site_role: ScalaCallableSiteRole,
    ) -> Vec<CodeUnit> {
        self.method_declarations_for_members_matching(
            scala,
            token,
            members,
            ScalaCallMatch::Shape(call_shape),
            site_role,
        )
    }

    fn callable_declarations_for_members<T: Borrow<CodeUnit>>(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        members: &[T],
        call_shape: Option<&ScalaCallSiteShape>,
        site_role: ScalaCallableSiteRole,
    ) -> Vec<CodeUnit> {
        match call_shape {
            Some(shape) => self.callable_declarations_for_members_with_shape(
                scala, token, members, shape, site_role,
            ),
            None => self.method_declarations_for_members_matching(
                scala,
                token,
                members,
                ScalaCallMatch::Arities(None),
                site_role,
            ),
        }
    }

    fn method_declarations_for_members_matching<T: Borrow<CodeUnit>>(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        members: &[T],
        call: ScalaCallMatch<'_>,
        site_role: ScalaCallableSiteRole,
    ) -> Vec<CodeUnit> {
        let candidates = members
            .iter()
            .map(Borrow::borrow)
            .filter(|method| method.is_function())
            .filter_map(|method| {
                self.callable_facts(scala, token, method).map(|facts| {
                    (
                        method,
                        facts,
                        self.effective_callable_alternatives_for(scala, token, method),
                    )
                })
            })
            .collect::<Vec<_>>();
        let callable_count = match call {
            ScalaCallMatch::Arities(_) => candidates
                .iter()
                .map(|(method, _, alternatives)| {
                    if alternatives.is_empty() {
                        usize::from(site_role.accepts(self.fallback_callable_role(scala, method)))
                    } else {
                        alternatives
                            .iter()
                            .filter(|alternative| site_role.accepts(alternative.role))
                            .count()
                    }
                })
                .sum::<usize>(),
            ScalaCallMatch::Shape(shape) => candidates
                .iter()
                .map(|(method, facts, alternatives)| {
                    if alternatives.is_empty() {
                        if shape.method_value_parameter_types_authoritative {
                            return 0;
                        }
                        let fallback = facts
                            .callable_arity
                            .or_else(|| facts.arity.map(CallableArity::exact))
                            .map(ScalaCallableParameterList::explicit)
                            .into_iter()
                            .collect::<Vec<_>>();
                        usize::from(scala_callable_alternative_is_candidate(
                            self.fallback_callable_role(scala, method),
                            &fallback,
                            ScalaDeclaredResult::UNDECLARED,
                            shape,
                            site_role,
                        ))
                    } else {
                        alternatives
                            .iter()
                            .filter(|alternative| {
                                callable_alternative_is_candidate(alternative, shape, site_role)
                            })
                            .count()
                    }
                })
                .sum::<usize>(),
        };
        let unique_callable = callable_count == 1;
        candidates
            .iter()
            .filter(|(method, facts, alternatives)| match call {
                ScalaCallMatch::Arities(call_arities) => callable_call_shape_matches(
                    facts,
                    alternatives,
                    call_arities,
                    self.fallback_callable_role(scala, method),
                    site_role,
                    unique_callable,
                ),
                ScalaCallMatch::Shape(shape) => {
                    if alternatives.is_empty() {
                        if shape.method_value_parameter_types_authoritative {
                            return false;
                        }
                        let fallback = facts
                            .callable_arity
                            .or_else(|| facts.arity.map(CallableArity::exact))
                            .map(ScalaCallableParameterList::explicit)
                            .into_iter()
                            .collect::<Vec<_>>();
                        scala_callable_alternative_matches(
                            self.fallback_callable_role(scala, method),
                            &fallback,
                            ScalaDeclaredResult::UNDECLARED,
                            Some(shape),
                            site_role,
                            unique_callable,
                        )
                    } else {
                        alternatives.iter().any(|alternative| {
                            callable_alternative_matches(
                                alternative,
                                Some(shape),
                                site_role,
                                unique_callable,
                            )
                        })
                    }
                }
            })
            .map(|(method, _, _)| (*method).clone())
            .collect()
    }

    fn imported_member_targets_with_shape(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        member_fqn: &str,
        call_shape: &ScalaCallSiteShape,
    ) -> Vec<CodeUnit> {
        let declarations = self.index.by_fqn(member_fqn);
        let members = declarations
            .iter()
            .filter(|unit| unit.is_function())
            .collect::<Vec<_>>();
        self.method_declarations_for_members_with_shape(scala, token, &members, call_shape)
    }

    pub fn bare_member_declarations_for_owner(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        owner: &CodeUnit,
        member: &str,
        call_arities: Option<&[usize]>,
    ) -> BareMemberResolution {
        self.bare_member_declarations_for_owner_matching(
            scala,
            token,
            owner,
            member,
            ScalaCallMatch::Arities(call_arities),
        )
    }

    fn exact_method_value_declaration_for_owner(
        &self,
        scala: &dyn ScalaSource,
        owner: &CodeUnit,
        member: &str,
    ) -> BareMemberResolution {
        if !owner.is_class() {
            return BareMemberResolution::NoMatch;
        }
        let mut owners = vec![owner.clone()];
        let mut seen = HashSet::default();
        while !owners.is_empty() {
            let mut matched = Vec::new();
            let mut declaring_owners = HashSet::default();
            let mut next = Vec::new();
            for owner in owners {
                if !seen.insert(owner.clone()) {
                    continue;
                }
                let members = self.members_for_exact_owner_unit(scala, &owner, member);
                if members
                    .iter()
                    .any(|member| self.member_blocks_callable_lookup(scala, member))
                {
                    return BareMemberResolution::Unresolved;
                }
                let mut methods = members
                    .into_iter()
                    .filter(|unit| unit.is_function())
                    .collect::<Vec<_>>();
                methods.sort();
                methods.dedup();
                if !methods.is_empty() {
                    declaring_owners.insert(owner.clone());
                    matched.extend(methods);
                }
                next.extend(self.direct_ancestors_for_declaration(scala, &owner));
            }
            // Two replicas of one owner are two distinct CodeUnit values and
            // would trip this count before the family gate below is ever
            // consulted, leaving this path fail-closed for cross-built symbols
            // no matter what that gate says (#2021).
            if declaring_owners.len() > 1 && !single_replica_family(declaring_owners.iter()) {
                return BareMemberResolution::Unresolved;
            }
            // A same-file overload family is one declaration (#1327), and a
            // coherent replica family is one declaration cross-built across
            // source sets (#2021); the method-value shape matching downstream
            // selects among their units.
            if matched.is_empty() {
                owners = next;
            } else if single_replica_family(matched.iter()) {
                return BareMemberResolution::Resolved(matched);
            } else {
                return BareMemberResolution::Unresolved;
            }
        }
        BareMemberResolution::NoMatch
    }

    fn bare_member_declarations_for_owner_matching(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        owner: &CodeUnit,
        member: &str,
        call: ScalaCallMatch<'_>,
    ) -> BareMemberResolution {
        if !owner.is_class() {
            return BareMemberResolution::NoMatch;
        }
        let mut owners = vec![owner.clone()];
        let mut seen = HashSet::default();
        while !owners.is_empty() {
            let mut matched = Vec::new();
            let mut declaring_owners = HashSet::default();
            let mut next = Vec::new();
            for owner in owners {
                if !seen.insert(owner.clone()) {
                    continue;
                }
                let members = self.members_for_exact_owner_unit(scala, &owner, member);
                if members
                    .iter()
                    .any(|member| self.member_blocks_callable_lookup(scala, member))
                {
                    return BareMemberResolution::Unresolved;
                }
                let methods = match call {
                    ScalaCallMatch::Arities(call_arities) => {
                        self.method_declarations_for_members(scala, token, &members, call_arities)
                    }
                    ScalaCallMatch::Shape(call_shape) => self
                        .method_declarations_for_members_with_shape(
                            scala, token, &members, call_shape,
                        ),
                };
                if !methods.is_empty() {
                    declaring_owners.insert(owner.clone());
                    matched.extend(methods);
                }
                next.extend(self.direct_ancestors_for_declaration(scala, &owner));
            }
            if declaring_owners.len() > 1 {
                return BareMemberResolution::Unresolved;
            }
            if !matched.is_empty() {
                let mut unique = HashSet::default();
                matched.retain(|method| unique.insert(method.clone()));
                return BareMemberResolution::Resolved(matched);
            }
            owners = next;
        }
        BareMemberResolution::NoMatch
    }

    /// Resolve only ordinary methods declared by a class, trait, or stable
    /// object owner.
    ///
    /// This intentionally does not broaden trait-default or extension-method
    /// handling.  Each breadth level is one semantic tier: fields, trait
    /// declarations, or methods from multiple class owners make that tier
    /// unresolved instead of allowing traversal order to choose a target.
    pub fn ordinary_class_member_declarations_for_owner(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        owner: &CodeUnit,
        member: &str,
        call_arities: Option<&[usize]>,
    ) -> BareMemberResolution {
        self.ordinary_class_member_declarations_for_owner_matching(
            scala,
            token,
            owner,
            member,
            ScalaCallMatch::Arities(call_arities),
        )
    }

    fn ordinary_class_member_declarations_for_owner_matching(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        owner: &CodeUnit,
        member: &str,
        call: ScalaCallMatch<'_>,
    ) -> BareMemberResolution {
        if !self.owner_supports_ordinary_member_lookup(scala, owner) {
            return BareMemberResolution::NoMatch;
        }
        self.ordinary_class_member_declarations_for_owners_matching(
            scala,
            token,
            std::slice::from_ref(owner),
            member,
            call,
        )
    }

    pub fn ordinary_class_member_declarations_for_owners(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        direct_owners: &[CodeUnit],
        member: &str,
        call_arities: Option<&[usize]>,
    ) -> BareMemberResolution {
        self.ordinary_class_member_declarations_for_owners_matching(
            scala,
            token,
            direct_owners,
            member,
            ScalaCallMatch::Arities(call_arities),
        )
    }

    fn ordinary_class_member_declarations_for_owners_matching(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        direct_owners: &[CodeUnit],
        member: &str,
        call: ScalaCallMatch<'_>,
    ) -> BareMemberResolution {
        let mut owners = direct_owners.to_vec();
        let mut seen = HashSet::default();
        while !owners.is_empty() {
            let mut matched = Vec::new();
            let mut declaring_owners = HashSet::default();
            let mut blocked = false;
            let mut next = Vec::new();
            for owner in owners {
                if !seen.insert(owner.clone()) {
                    continue;
                }
                if call.is_unapplied()
                    && self
                        .exact_nested_object(scala, &owner.fq_name(), member)
                        .is_some()
                {
                    blocked = true;
                }
                let members = self.members_for_exact_owner_unit(scala, &owner, member);
                if members
                    .iter()
                    .any(|member| self.member_blocks_callable_lookup(scala, member))
                {
                    blocked = true;
                }
                let methods = match call {
                    ScalaCallMatch::Arities(call_arities) => {
                        self.method_declarations_for_members(scala, token, &members, call_arities)
                    }
                    ScalaCallMatch::Shape(call_shape) => self
                        .method_declarations_for_members_with_shape(
                            scala, token, &members, call_shape,
                        ),
                };
                if !methods.is_empty() {
                    if self.is_scala_trait_declaration(scala, &owner) {
                        if methods
                            .iter()
                            .any(|method| !self.is_abstract_scala_method(scala, method))
                        {
                            blocked = true;
                        }
                    } else if methods.iter().any(|method| {
                        self.extension_method_for_unit(scala, token, method)
                            .is_some()
                    }) {
                        blocked = true;
                    } else {
                        declaring_owners.insert(owner.clone());
                        matched.extend(methods);
                    }
                }
                next.extend(self.direct_ancestors_for_declaration(scala, &owner));
            }
            if blocked || declaring_owners.len() > 1 {
                return BareMemberResolution::Unresolved;
            }
            if !matched.is_empty() {
                let mut unique = HashSet::default();
                matched.retain(|method| unique.insert(method.clone()));
                return BareMemberResolution::Resolved(matched);
            }
            owners = next;
        }
        BareMemberResolution::NoMatch
    }

    pub fn is_abstract_scala_method(&self, scala: &dyn ScalaSource, method: &CodeUnit) -> bool {
        let ranges = self.declaration_ranges_for(scala, method);
        !ranges.is_empty()
            && ranges.iter().all(|range| {
                self.source_facts_for_file(scala, method.source())
                    .abstract_callable_ranges
                    .contains(&(range.start_byte, range.end_byte))
            })
    }

    fn member_blocks_callable_lookup(&self, scala: &dyn ScalaSource, member: &CodeUnit) -> bool {
        self.has_term_field_declaration(member)
            || member.is_class() && self.type_is_stable_owner(scala, member)
    }

    /// Whether `member` blocks resolving `call` to a same-named callable of the
    /// owner that declares it.
    ///
    /// A `val` and a `def` can share one name in one Scala template only when
    /// the `def` takes parameters. An unapplied reference is therefore the
    /// `val`, and letting it reach the `def` would attribute a plain read to a
    /// method. An application carries argument lists the `val` does not
    /// declare, so the shape filter below selects the `def` and the `val` does
    /// not block it. A nested stable object blocks either way: `Nested(...)` is
    /// that object's `apply`, not an ordinary method of the enclosing owner.
    fn member_blocks_callable_lookup_for_call(
        &self,
        scala: &dyn ScalaSource,
        member: &CodeUnit,
        call: ScalaCallMatch<'_>,
    ) -> bool {
        if member.is_class() && self.type_is_stable_owner(scala, member) {
            return true;
        }
        call.is_unapplied() && self.has_term_field_declaration(member)
    }

    pub fn callable_parameter_function_shape(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        method: &CodeUnit,
        call_arities: &[usize],
        parameter_list: usize,
        parameter_index: usize,
    ) -> Option<ScalaFunctionParameterShape> {
        let alternatives = self.callable_alternatives_for(scala, token, method);
        let mut resolved = None;
        for alternative in alternatives.iter().filter(|alternative| {
            alternative.role == ScalaCallableRole::Ordinary
                && ordinary_callable_shape_matches(alternative, Some(call_arities), true)
        }) {
            let shape = alternative
                .parameter_function_shapes
                .get(parameter_list)
                .and_then(|parameters| parameters.get(parameter_index))
                .cloned()
                .flatten()?;
            if resolved.as_ref().is_some_and(|resolved| resolved != &shape) {
                return None;
            }
            resolved = Some(shape);
        }
        resolved
    }

    /// Resolve the callable selected for a receiver's static owner.
    ///
    /// Scala mixin linearization gives the rightmost parent and its ancestry
    /// precedence over parents to its left. Abstract inherited trait contracts
    /// remain a fallback only when the linearization supplies no concrete
    /// implementation.
    fn effective_method_declarations_for_owner(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        owner_fqn: &str,
        member: &str,
        call_arities: Option<&[usize]>,
    ) -> BareMemberResolution {
        self.effective_method_declarations_for_owner_matching(
            scala,
            token,
            owner_fqn,
            member,
            ScalaCallMatch::Arities(call_arities),
        )
    }

    fn effective_method_declarations_for_owner_with_shape(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        owner_fqn: &str,
        member: &str,
        call_shape: &ScalaCallSiteShape,
    ) -> BareMemberResolution {
        self.effective_method_declarations_for_owner_matching(
            scala,
            token,
            owner_fqn,
            member,
            ScalaCallMatch::Shape(call_shape),
        )
    }

    fn effective_method_declarations_for_owner_matching(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        owner_fqn: &str,
        member: &str,
        call: ScalaCallMatch<'_>,
    ) -> BareMemberResolution {
        let owner_declarations = self.index.by_fqn(owner_fqn);
        let mut declarations = owner_declarations
            .iter()
            .filter(|owner| self.owner_supports_ordinary_member_lookup(scala, owner));
        let Some(owner) = declarations.next() else {
            return BareMemberResolution::NoMatch;
        };
        if declarations.next().is_some() {
            return BareMemberResolution::Unresolved;
        }

        self.effective_method_declarations_for_exact_owner_matching(
            scala, token, owner, member, call,
        )
    }

    fn effective_method_declarations_for_exact_owner_with_shape(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        owner: &CodeUnit,
        member: &str,
        call_shape: &ScalaCallSiteShape,
    ) -> BareMemberResolution {
        self.effective_method_declarations_for_exact_owner_matching(
            scala,
            token,
            owner,
            member,
            ScalaCallMatch::Shape(call_shape),
        )
    }

    fn effective_method_declarations_for_exact_owner(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        owner: &CodeUnit,
        member: &str,
        call_arities: Option<&[usize]>,
    ) -> BareMemberResolution {
        self.effective_method_declarations_for_exact_owner_matching(
            scala,
            token,
            owner,
            member,
            ScalaCallMatch::Arities(call_arities),
        )
    }

    fn effective_method_declarations_for_exact_owner_matching(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        owner: &CodeUnit,
        member: &str,
        call: ScalaCallMatch<'_>,
    ) -> BareMemberResolution {
        if !self.owner_supports_ordinary_member_lookup(scala, owner) {
            return BareMemberResolution::NoMatch;
        }

        let root_owner = owner.clone();
        let linearized = self.linearized_owners(scala, &root_owner);
        let mut abstract_trait_fallback = None;
        for owner in &linearized {
            if call.is_unapplied()
                && !self
                    .exact_nested_objects_for_owner(scala, owner, member)
                    .is_empty()
            {
                return BareMemberResolution::Unresolved;
            }
            let members = self.members_for_exact_owner_unit(scala, owner, member);
            if members
                .iter()
                .any(|member| self.member_blocks_callable_lookup_for_call(scala, member, call))
            {
                return BareMemberResolution::Unresolved;
            }
            let methods = match call {
                ScalaCallMatch::Arities(call_arities) => {
                    self.method_declarations_for_members(scala, token, &members, call_arities)
                }
                ScalaCallMatch::Shape(shape) => {
                    self.method_declarations_for_members_with_shape(scala, token, &members, shape)
                }
            };
            if !methods.is_empty() {
                let replica_conflict = linearized.iter().any(|replica| {
                    if replica == owner || replica.fq_name() != owner.fq_name() {
                        return false;
                    }
                    if call.is_unapplied()
                        && !self
                            .exact_nested_objects_for_owner(scala, replica, member)
                            .is_empty()
                    {
                        return true;
                    }
                    let replica_members = self.members_for_exact_owner_unit(scala, replica, member);
                    if replica_members.iter().any(|member| {
                        self.member_blocks_callable_lookup_for_call(scala, member, call)
                    }) {
                        return true;
                    }
                    match call {
                        ScalaCallMatch::Arities(call_arities) => !self
                            .method_declarations_for_members(
                                scala,
                                token,
                                &replica_members,
                                call_arities,
                            )
                            .is_empty(),
                        ScalaCallMatch::Shape(shape) => !self
                            .method_declarations_for_members_with_shape(
                                scala,
                                token,
                                &replica_members,
                                shape,
                            )
                            .is_empty(),
                    }
                });
                if replica_conflict {
                    return BareMemberResolution::Unresolved;
                }
                let inherited_abstract_trait = owner != &root_owner
                    && self.is_scala_trait_declaration(scala, owner)
                    && methods
                        .iter()
                        .all(|method| self.is_abstract_scala_method(scala, method));
                if inherited_abstract_trait {
                    abstract_trait_fallback.get_or_insert(methods);
                } else {
                    return BareMemberResolution::Resolved(methods);
                }
            }
        }
        abstract_trait_fallback.map_or(
            BareMemberResolution::NoMatch,
            BareMemberResolution::Resolved,
        )
    }

    /// The declaration `super.m` names inside `owner`. An up-call is answered by
    /// the parent linearization, so `owner`'s own declaration is skipped: in
    /// `class C extends B { override def m() = super.m() }` the call names
    /// `B.m`, not `C.m`. The first parent tier that declares the member wins,
    /// exactly as ordinary member lookup treats the tiers below it.
    fn super_method_declarations(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        owner: &CodeUnit,
        member: &str,
        call: ScalaCallMatch<'_>,
    ) -> BareMemberResolution {
        if !self.owner_supports_ordinary_member_lookup(scala, owner) {
            return BareMemberResolution::NoMatch;
        }
        for tier in self.linearized_owners(scala, owner).into_iter().skip(1) {
            let members = self.members_for_exact_owner_unit(scala, &tier, member);
            if members
                .iter()
                .any(|member| self.member_blocks_callable_lookup_for_call(scala, member, call))
            {
                return BareMemberResolution::Unresolved;
            }
            let methods = match call {
                ScalaCallMatch::Arities(call_arities) => {
                    self.method_declarations_for_members(scala, token, &members, call_arities)
                }
                ScalaCallMatch::Shape(shape) => {
                    self.method_declarations_for_members_with_shape(scala, token, &members, shape)
                }
            };
            if !methods.is_empty() {
                return BareMemberResolution::Resolved(methods);
            }
        }
        BareMemberResolution::NoMatch
    }

    fn owner_supports_ordinary_member_lookup(
        &self,
        scala: &dyn ScalaSource,
        owner: &CodeUnit,
    ) -> bool {
        owner.is_class()
            || self.is_scala_trait_declaration(scala, owner)
            || self.type_is_stable_owner(scala, owner)
    }

    /// Compute Scala's duplicate-eliding parent linearization without Rust
    /// recursion. For `C extends L with R`, the parent suffix is
    /// `L(R) ⊕ L(L)`: identities repeated by the later/left linearization are
    /// removed from the earlier/right one before the lists are joined.
    fn linearized_owners(&self, scala: &dyn ScalaSource, root: &CodeUnit) -> Vec<CodeUnit> {
        let mut completed = HashMap::<CodeUnit, Vec<CodeUnit>>::default();
        let mut visiting = HashSet::default();
        let mut stack = vec![(root.clone(), false)];

        while let Some((owner, expanded)) = stack.pop() {
            if completed.contains_key(&owner) {
                continue;
            }
            if expanded {
                visiting.remove(&owner);
                let mut suffix = Vec::new();
                for parent in self
                    .direct_ancestors_for_declaration(scala, &owner)
                    .into_iter()
                    .rev()
                {
                    let Some(parent_linearization) = completed.get(&parent) else {
                        // A missing entry denotes a cyclic edge that was not
                        // rescheduled while its owner was already active.
                        continue;
                    };
                    let parent_owners = parent_linearization.iter().collect::<HashSet<_>>();
                    suffix.retain(|existing| !parent_owners.contains(existing));
                    suffix.extend(parent_linearization.iter().cloned());
                }
                let mut linearization = Vec::with_capacity(1 + suffix.len());
                linearization.push(owner.clone());
                linearization.extend(suffix);
                completed.insert(owner, linearization);
                continue;
            }
            if !visiting.insert(owner.clone()) {
                continue;
            }
            stack.push((owner.clone(), true));
            for parent in self.direct_ancestors_for_declaration(scala, &owner) {
                if !completed.contains_key(&parent) && !visiting.contains(&parent) {
                    stack.push((parent, false));
                }
            }
        }

        completed.remove(root).unwrap_or_else(|| vec![root.clone()])
    }

    fn generic_owner_source_facts(
        &self,
        scala: &dyn ScalaSource,
        owner: &CodeUnit,
    ) -> Option<ScalaGenericOwnerSourceFacts> {
        let source_facts = self.source_facts_for_file(scala, owner.source());
        let mut matches = self
            .declaration_ranges_for(scala, owner)
            .into_iter()
            .filter_map(|range| {
                source_facts
                    .generic_owner_facts_by_range
                    .get(&(range.start_byte, range.end_byte))
                    .cloned()
            });
        let first = matches.next()?;
        matches.all(|facts| facts == first).then_some(first)
    }

    fn concrete_type_expression_owner(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        declaration: &CodeUnit,
        expression: &ScalaTypeExpressionPath,
    ) -> Option<CodeUnit> {
        let resolver = NameResolver::for_file_types(scala, token, declaration, self);
        let fqn = self.resolve_type_in_callable_declaration_context(
            scala,
            &resolver,
            declaration,
            &expression.segments,
        )?;
        match self.exact_type_declaration_for_owner_context(&fqn, declaration) {
            ScalaTypeNamespaceResolution::Resolved(owner) => Some(owner),
            ScalaTypeNamespaceResolution::AuthoritativeMiss
            | ScalaTypeNamespaceResolution::Ambiguous(_)
            | ScalaTypeNamespaceResolution::NoMatch => None,
        }
    }

    fn generic_environments_for_linearization(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        root: &CodeUnit,
    ) -> Option<HashMap<CodeUnit, HashMap<String, CodeUnit>>> {
        let mut environments = HashMap::<CodeUnit, HashMap<String, CodeUnit>>::default();
        environments.insert(root.clone(), HashMap::default());
        let mut pending = vec![root.clone()];
        let mut expanded = HashSet::default();
        while let Some(owner) = pending.pop() {
            if !expanded.insert(owner.clone()) {
                continue;
            }
            let environment = environments.get(&owner)?.clone();
            let owner_facts = self.generic_owner_source_facts(scala, &owner)?;
            let direct_ancestors = match self.exact_direct_ancestor_resolution(scala, token, &owner)
            {
                ScalaDirectAncestorResolution::Resolved(ancestors)
                | ScalaDirectAncestorResolution::Incomplete(ancestors) => ancestors,
                ScalaDirectAncestorResolution::Ambiguous => return None,
            };
            for ancestor in direct_ancestors {
                let mut matching_expressions = owner_facts.supertypes.iter().filter(|expression| {
                    self.concrete_type_expression_owner(scala, token, &owner, expression)
                        .as_ref()
                        == Some(&ancestor)
                });
                let expression = matching_expressions.next()?;
                if matching_expressions.next().is_some() {
                    return None;
                }
                let ancestor_facts = self.generic_owner_source_facts(scala, &ancestor)?;
                if ancestor_facts.type_parameters.len() != expression.arguments.len() {
                    return None;
                }
                let mut ancestor_environment = HashMap::default();
                for (parameter, argument) in ancestor_facts
                    .type_parameters
                    .iter()
                    .zip(&expression.arguments)
                {
                    let value = if argument.arguments.is_empty()
                        && argument.segments.len() == 1
                        && owner_facts
                            .type_parameters
                            .iter()
                            .any(|candidate| candidate == &argument.segments[0])
                    {
                        environment.get(&argument.segments[0]).cloned()
                    } else {
                        self.concrete_type_expression_owner(scala, token, &owner, argument)
                    }?;
                    ancestor_environment.insert(parameter.clone(), value);
                }
                if environments
                    .get(&ancestor)
                    .is_some_and(|existing| existing != &ancestor_environment)
                {
                    return None;
                }
                if environments
                    .insert(ancestor.clone(), ancestor_environment)
                    .is_none()
                {
                    pending.push(ancestor);
                }
            }
        }
        Some(environments)
    }

    fn callable_return_value_from_path(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        method: &CodeUnit,
        declaring_owner: &CodeUnit,
        environment: &HashMap<String, CodeUnit>,
        return_path: &[String],
    ) -> Option<ScalaValueOwner> {
        if return_path.len() == 1
            && let Some(owner) = environment.get(&return_path[0])
        {
            return Some(ScalaValueOwner::Exact(owner.clone()));
        }
        let owner_facts = self.generic_owner_source_facts(scala, declaring_owner)?;
        if return_path.len() == 1
            && owner_facts
                .type_parameters
                .iter()
                .any(|parameter| parameter == &return_path[0])
        {
            return None;
        }
        let resolver = NameResolver::for_file_types(scala, token, method, self);
        let fqn = self.resolve_type_in_callable_declaration_context(
            scala,
            &resolver,
            method,
            return_path,
        )?;
        match self.exact_type_declaration_for_owner_context(&fqn, method) {
            ScalaTypeNamespaceResolution::Resolved(owner) => Some(ScalaValueOwner::Exact(owner)),
            ScalaTypeNamespaceResolution::NoMatch => Some(ScalaValueOwner::Logical(fqn)),
            ScalaTypeNamespaceResolution::AuthoritativeMiss
            | ScalaTypeNamespaceResolution::Ambiguous(_) => None,
        }
    }

    fn callable_value_resolution_for_members<T: Borrow<CodeUnit>>(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        declaring_owner: &CodeUnit,
        members: &[T],
        call_shape: Option<&ScalaCallSiteShape>,
        environment: &HashMap<String, CodeUnit>,
    ) -> ScalaCallableTierResolution {
        if members
            .iter()
            .map(Borrow::borrow)
            .any(|member| self.member_blocks_callable_lookup(scala, member))
        {
            return ScalaCallableTierResolution::NoApplicableCallable;
        }
        let mut source_candidates = Vec::new();
        for method in members
            .iter()
            .map(Borrow::borrow)
            .filter(|member| member.is_function())
        {
            let source_facts = self.source_facts_for_file(scala, method.source());
            for range in self.declaration_ranges_for(scala, method) {
                if let Some(alternative) = source_facts
                    .callable_alternatives_by_range
                    .get(&(range.start_byte, range.end_byte))
                    .filter(|alternative| alternative.role == ScalaCallableRole::Ordinary)
                {
                    source_candidates.push((method, alternative.clone()));
                }
            }
        }
        let candidate_count = source_candidates
            .iter()
            .filter(|(_, alternative)| {
                call_shape.is_none_or(|shape| {
                    scala_callable_alternative_is_candidate(
                        alternative.role,
                        &alternative.shape,
                        alternative.result,
                        shape,
                        ScalaCallableSiteRole::Ordinary,
                    )
                })
            })
            .count();
        let unique_callable = candidate_count == 1;
        let mut callable_targets = Vec::new();
        let mut value_result = None;
        let mut saw_unknown_return = false;
        for (method, alternative) in source_candidates {
            if !scala_callable_alternative_matches(
                alternative.role,
                &alternative.shape,
                alternative.result,
                call_shape,
                ScalaCallableSiteRole::Ordinary,
                unique_callable,
            ) {
                continue;
            }
            let value = alternative
                .return_type_path
                .as_deref()
                .and_then(|return_path| {
                    self.callable_return_value_from_path(
                        scala,
                        token,
                        method,
                        declaring_owner,
                        environment,
                        return_path,
                    )
                });
            let Some(value) = value else {
                callable_targets.push(method.clone());
                saw_unknown_return = true;
                continue;
            };
            if value_result
                .as_ref()
                .is_some_and(|resolved| resolved != &value)
            {
                callable_targets.push(method.clone());
                value_result = None;
                saw_unknown_return = true;
                continue;
            }
            value_result = Some(value);
            callable_targets.push(method.clone());
        }
        callable_targets.sort();
        callable_targets.dedup();
        if callable_targets.is_empty() {
            return ScalaCallableTierResolution::NoApplicableCallable;
        }
        ScalaCallableTierResolution::Applicable(Some(ScalaCallableValueResolution {
            callable_targets,
            value_result: (!saw_unknown_return).then_some(value_result).flatten(),
        }))
    }

    fn inherited_apply_value_resolution(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        root: &CodeUnit,
        call_shape: Option<&ScalaCallSiteShape>,
    ) -> ScalaApplyValueResolution {
        let root_members = self.members_for_exact_owner_unit(scala, root, "apply");
        if !root_members.is_empty() {
            // A direct declaration is authoritative without consulting an
            // unrelated or ambiguous ancestor hierarchy. Objects cannot
            // introduce type parameters of their own, so this tier starts
            // with an empty substitution environment.
            return match self.callable_value_resolution_for_members(
                scala,
                token,
                root,
                &root_members,
                call_shape,
                &HashMap::default(),
            ) {
                ScalaCallableTierResolution::NoApplicableCallable => {
                    ScalaApplyValueResolution::NoApplicableCallable
                }
                ScalaCallableTierResolution::Applicable(resolution) => {
                    ScalaApplyValueResolution::Authoritative(resolution)
                }
            };
        }
        let mut declaring_tier = None;
        for owner in self.linearized_owners(scala, root).into_iter().skip(1) {
            let members = self.members_for_exact_owner_unit(scala, &owner, "apply");
            if !members.is_empty() {
                declaring_tier = Some((owner, members));
                break;
            }
        }
        let Some((owner, members)) = declaring_tier else {
            return ScalaApplyValueResolution::NoDeclaration;
        };
        // The first declaring tier is authoritative even if its overloads,
        // return type, or generic substitution cannot be proven.
        let resolution = self
            .generic_environments_for_linearization(scala, token, root)
            .and_then(|environments| {
                let environment = environments.get(&owner)?;
                Some(self.callable_value_resolution_for_members(
                    scala,
                    token,
                    &owner,
                    &members,
                    call_shape,
                    environment,
                ))
            });
        match resolution {
            Some(ScalaCallableTierResolution::NoApplicableCallable) => {
                ScalaApplyValueResolution::NoApplicableCallable
            }
            Some(ScalaCallableTierResolution::Applicable(resolution)) => {
                ScalaApplyValueResolution::Authoritative(resolution)
            }
            None => ScalaApplyValueResolution::Authoritative(None),
        }
    }

    pub fn member_return_type(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        resolver: &NameResolver,
        member_fqn: &str,
    ) -> Option<String> {
        let mut resolved_return = None;
        let mut matched = false;
        for unit in self
            .index
            .by_fqn(member_fqn)
            .iter()
            .filter(|unit| unit.is_function())
        {
            let alternatives = self.callable_alternatives_for(scala, token, unit);
            if alternatives.is_empty() {
                let return_type = self
                    .callable_facts(scala, token, unit)
                    .and_then(|facts| facts.return_type_fqn.clone())?;
                if resolved_return
                    .as_ref()
                    .is_some_and(|resolved| resolved != &return_type)
                {
                    return None;
                }
                resolved_return = Some(return_type);
                matched = true;
                continue;
            }
            for alternative in alternatives
                .iter()
                .filter(|alternative| alternative.role == ScalaCallableRole::Ordinary)
            {
                let return_type = alternative
                    .return_type
                    .as_deref()
                    .and_then(|return_type| self.resolve_type_text(resolver, return_type))?;
                if resolved_return
                    .as_ref()
                    .is_some_and(|resolved| resolved != &return_type)
                {
                    return None;
                }
                resolved_return = Some(return_type);
                matched = true;
            }
        }
        matched.then_some(resolved_return).flatten()
    }

    pub fn member_return_type_for_owner_member(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        resolver: &NameResolver,
        owner_fqn: &str,
        member: &str,
        call_arities: Option<&[usize]>,
    ) -> Option<String> {
        let members = self.members_for_exact_owner_name(owner_fqn, member);
        self.member_return_type_for_members(scala, token, resolver, &members, call_arities)
    }

    pub fn member_return_type_for_fqn_call(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        resolver: &NameResolver,
        member_fqn: &str,
        call_arities: Option<&[usize]>,
    ) -> Option<String> {
        let declarations = self.index.by_fqn(member_fqn);
        let members = declarations.iter().collect::<Vec<_>>();
        self.member_return_type_for_members(scala, token, resolver, &members, call_arities)
    }

    fn member_return_type_for_members<T: Borrow<CodeUnit>>(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        resolver: &NameResolver,
        members: &[T],
        call_arities: Option<&[usize]>,
    ) -> Option<String> {
        let call_shape = call_arities.map(ScalaCallSiteShape::ordinary);
        self.member_return_type_for_members_with_shape(
            scala,
            token,
            resolver,
            members,
            call_shape.as_ref(),
        )
    }

    fn member_return_type_for_members_with_shape<T: Borrow<CodeUnit>>(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        resolver: &NameResolver,
        members: &[T],
        call_shape: Option<&ScalaCallSiteShape>,
    ) -> Option<String> {
        let candidates = members
            .iter()
            .map(Borrow::borrow)
            .filter(|method| method.is_function())
            .filter_map(|method| {
                self.callable_facts(scala, token, method).map(|facts| {
                    (
                        method,
                        facts,
                        self.callable_alternatives_for(scala, token, method),
                    )
                })
            })
            .collect::<Vec<_>>();
        let callable_count = candidates
            .iter()
            .map(|(method, _, alternatives)| {
                if alternatives.is_empty() {
                    usize::from(
                        self.fallback_callable_role(scala, method) == ScalaCallableRole::Ordinary,
                    )
                } else {
                    alternatives
                        .iter()
                        .filter(|alternative| {
                            alternative.role == ScalaCallableRole::Ordinary
                                && call_shape.is_none_or(|actual| {
                                    scala_callable_alternative_is_candidate(
                                        alternative.role,
                                        &alternative.shape,
                                        alternative.result,
                                        actual,
                                        ScalaCallableSiteRole::Ordinary,
                                    )
                                })
                        })
                        .count()
                }
            })
            .sum::<usize>();
        let unique_callable = callable_count == 1;
        let mut resolved_return = None;
        let mut matched = false;
        for (method, facts, alternatives) in candidates {
            if alternatives.is_empty() {
                let fallback_shape = facts
                    .callable_arity
                    .or_else(|| facts.arity.map(CallableArity::exact))
                    .map(ScalaCallableParameterList::explicit)
                    .into_iter()
                    .collect::<Vec<_>>();
                if !scala_callable_alternative_matches(
                    self.fallback_callable_role(scala, method),
                    &fallback_shape,
                    ScalaDeclaredResult::UNDECLARED,
                    call_shape,
                    ScalaCallableSiteRole::Ordinary,
                    unique_callable,
                ) {
                    continue;
                }
                let return_type = facts.return_type_fqn.clone()?;
                if resolved_return
                    .as_ref()
                    .is_some_and(|resolved| resolved != &return_type)
                {
                    return None;
                }
                resolved_return = Some(return_type);
                matched = true;
                continue;
            }
            for alternative in alternatives.iter().filter(|alternative| {
                scala_callable_alternative_matches(
                    alternative.role,
                    &alternative.shape,
                    alternative.result,
                    call_shape,
                    ScalaCallableSiteRole::Ordinary,
                    unique_callable,
                )
            }) {
                let return_type = alternative
                    .return_type
                    .as_deref()
                    .and_then(|return_type| self.resolve_type_text(resolver, return_type))?;
                if resolved_return
                    .as_ref()
                    .is_some_and(|resolved| resolved != &return_type)
                {
                    return None;
                }
                resolved_return = Some(return_type);
                matched = true;
            }
        }
        matched.then_some(resolved_return).flatten()
    }

    pub fn unqualified_member_return_type(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        resolver: &NameResolver,
        owner: &CodeUnit,
        member: &str,
        call_arities: Option<&[usize]>,
    ) -> MemberReturnResolution {
        if !owner.is_class() {
            return MemberReturnResolution::NoMatch;
        }
        self.unqualified_member_return_type_for_owners(
            scala,
            token,
            resolver,
            std::slice::from_ref(owner),
            member,
            call_arities,
        )
    }

    pub fn unqualified_member_return_type_for_owners(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        resolver: &NameResolver,
        direct_owners: &[CodeUnit],
        member: &str,
        call_arities: Option<&[usize]>,
    ) -> MemberReturnResolution {
        let mut level = direct_owners.to_vec();

        let mut seen = HashSet::default();
        let mut saw_member = false;
        while !level.is_empty() {
            let mut matched_return = None;
            let mut matched = false;
            let mut next = Vec::new();
            for owner in level {
                if !seen.insert(owner.clone()) {
                    continue;
                }
                let owner_fqn = owner.fq_name();
                if call_arities.is_none()
                    && self
                        .exact_nested_object(scala, &owner_fqn, member)
                        .is_some()
                {
                    return MemberReturnResolution::Unresolved;
                }
                let members = self.members_for_exact_owner_unit(scala, &owner, member);
                saw_member |= !members.is_empty();
                if members
                    .iter()
                    .any(|unit| self.member_blocks_callable_lookup(scala, unit))
                {
                    return MemberReturnResolution::Unresolved;
                }
                if !self
                    .method_declarations_for_members(scala, token, &members, call_arities)
                    .is_empty()
                {
                    matched = true;
                    let Some(return_type) = self.member_return_type_for_members(
                        scala,
                        token,
                        resolver,
                        &members,
                        call_arities,
                    ) else {
                        return MemberReturnResolution::Unresolved;
                    };
                    if matched_return
                        .as_ref()
                        .is_some_and(|resolved| resolved != &return_type)
                    {
                        return MemberReturnResolution::Unresolved;
                    }
                    matched_return = Some(return_type);
                }
                next.extend(self.direct_ancestors_for_declaration(scala, &owner));
            }
            if matched {
                return matched_return
                    .map(MemberReturnResolution::Resolved)
                    .unwrap_or(MemberReturnResolution::Unresolved);
            }
            level = next;
        }
        if saw_member {
            MemberReturnResolution::Unresolved
        } else {
            MemberReturnResolution::NoMatch
        }
    }

    fn members_for_exact_owner_name(&self, owner: &str, member: &str) -> Vec<CodeUnit> {
        let mut members =
            self.index
                .members_for_owner_name(owner, &scala_normalized_fq_name(owner), member);
        if self.index.fqn_exists(owner) {
            members.retain(|unit| owner_fqn(unit).as_deref() == Some(owner));
        }
        members
    }

    fn members_for_exact_owner_unit(
        &self,
        scala: &dyn ScalaSource,
        owner: &CodeUnit,
        member: &str,
    ) -> Vec<CodeUnit> {
        self.index
            .members_for_structured_owner(owner.fq(), member)
            .into_iter()
            .filter(|unit| unit.source() == owner.source())
            .filter(|unit| self.is_exact_structural_child(scala, owner, unit))
            .collect()
    }

    pub fn exact_member_declarations(
        &self,
        scala: &dyn ScalaSource,
        owner: &CodeUnit,
        member: &str,
    ) -> Vec<CodeUnit> {
        self.members_for_exact_owner_unit(scala, owner, member)
    }

    fn package_types_in(&self, package: &str) -> PackageTypeEntries {
        if let Some(types) = self
            .package_types_by_package
            .lock()
            .expect("package type cache poisoned")
            .get(package)
            .cloned()
        {
            return types;
        }
        let mut grouped: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        for (simple, units) in self.index.package_types_in(package) {
            grouped.entry(simple).or_default().extend(
                units
                    .iter()
                    .filter(|unit| is_package_level_type(unit))
                    .cloned(),
            );
        }
        for alias in self
            .type_aliases
            .iter()
            .filter(|unit| unit.package_name() == package && is_package_level_type(unit))
        {
            grouped
                .entry(scala_simple_type_name(alias))
                .or_default()
                .push(alias.clone());
        }

        let mut values = Vec::new();
        for (simple, mut package_level) in grouped {
            package_level.sort();
            package_level.dedup();
            let ordinary = package_level
                .iter()
                .filter(|unit| {
                    self.type_aliases.contains(*unit) || !unit.short_name().ends_with('$')
                })
                .collect::<Vec<_>>();
            let selected = if ordinary.is_empty() {
                package_level.iter().collect::<Vec<_>>()
            } else {
                ordinary
            };
            for unit in selected {
                values.push((simple.clone(), unit.clone()));
            }
        }
        let values = Arc::new(values);
        self.package_types_by_package
            .lock()
            .expect("package type cache poisoned")
            .insert(package.to_string(), values.clone());
        values
    }

    fn type_by_normalized_fqn(&self, normalized_fqn: &str) -> Option<CodeUnit> {
        let units = self.index.by_normalized_fqn(normalized_fqn);
        preferred_scala_type(
            units
                .iter()
                .filter(|unit| self.is_type_namespace_declaration(unit)),
        )
        .cloned()
    }

    fn object_by_normalized_fqn(
        &self,
        scala: &dyn ScalaSource,
        normalized_fqn: &str,
    ) -> Option<CodeUnit> {
        let units = self.index.by_normalized_fqn(normalized_fqn);
        units
            .iter()
            .find(|unit| unit.is_class() && unit.short_name().ends_with('$'))
            .or_else(|| {
                preferred_scala_type(
                    units
                        .iter()
                        .filter(|unit| unit.is_class())
                        .filter(|unit| self.type_accepts_object_roles(scala, unit)),
                )
            })
            .cloned()
    }

    fn unique_type_by_normalized_fqn(&self, normalized_fqn: &str) -> Option<CodeUnit> {
        let units = self.index.by_normalized_fqn(normalized_fqn);
        let classes = units
            .iter()
            .filter(|unit| self.is_type_namespace_declaration(unit))
            .collect::<Vec<_>>();
        let ordinary = classes
            .iter()
            .copied()
            .filter(|unit| self.type_aliases.contains(*unit) || !unit.short_name().ends_with('$'))
            .collect::<Vec<_>>();
        let selected = if ordinary.is_empty() {
            classes
        } else {
            ordinary
        };
        let [resolved] = selected.as_slice() else {
            return None;
        };
        Some((*resolved).clone())
    }

    fn logical_type_by_normalized_fqn(&self, normalized_fqn: &str) -> Option<String> {
        let units = self.index.by_normalized_fqn(normalized_fqn);
        let classes = units
            .iter()
            .filter(|unit| self.is_type_namespace_declaration(unit))
            .collect::<Vec<_>>();
        let ordinary = classes
            .iter()
            .copied()
            .filter(|unit| self.type_aliases.contains(*unit) || !unit.short_name().ends_with('$'))
            .collect::<Vec<_>>();
        let selected = if ordinary.is_empty() {
            classes
        } else {
            ordinary
        };
        let logical = selected
            .iter()
            .map(|unit| unit.fq_name())
            .collect::<HashSet<_>>();
        (logical.len() == 1)
            .then(|| logical.into_iter().next())
            .flatten()
    }

    fn unique_object_by_normalized_fqn(
        &self,
        scala: &dyn ScalaSource,
        normalized_fqn: &str,
    ) -> Option<CodeUnit> {
        let units = self.index.by_normalized_fqn(normalized_fqn);
        let explicit = units
            .iter()
            .filter(|unit| unit.is_class() && unit.short_name().ends_with('$'))
            .collect::<Vec<_>>();
        if let [resolved] = explicit.as_slice() {
            return Some((*resolved).clone());
        }
        if !explicit.is_empty() {
            return None;
        }
        let accepting = units
            .iter()
            .filter(|unit| unit.is_class() && self.type_accepts_object_roles(scala, unit))
            .collect::<Vec<_>>();
        let [resolved] = accepting.as_slice() else {
            return None;
        };
        Some((*resolved).clone())
    }

    fn explicit_import_tier(
        &self,
        path: &str,
        package_prefixes: &[String],
    ) -> Option<ScalaExplicitImportTier> {
        resolve_scala_explicit_import_tier(path, package_prefixes, |candidate| {
            let normalized = scala_normalized_fq_name(candidate);
            ScalaExplicitImportFacts {
                declaration: !self.index.by_normalized_fqn(&normalized).is_empty(),
                package: self.index.package_exists(&normalized),
            }
        })
    }

    fn explicit_import_type_declarations(&self, candidate: &str) -> (Vec<CodeUnit>, Vec<CodeUnit>) {
        let normalized = scala_normalized_fq_name(candidate);
        let units = self.index.by_normalized_fqn(&normalized);
        let classes = units
            .iter()
            .filter(|unit| self.is_type_namespace_declaration(unit))
            .collect::<Vec<_>>();
        let ordinary = classes
            .iter()
            .copied()
            .filter(|unit| self.type_aliases.contains(*unit) || !unit.short_name().ends_with('$'))
            .cloned()
            .collect::<Vec<_>>();
        let type_declarations = if ordinary.is_empty() {
            classes.iter().map(|unit| (*unit).clone()).collect()
        } else {
            ordinary
        };
        let object_declarations = classes
            .iter()
            .copied()
            .filter(|unit| unit.is_class() && unit.short_name().ends_with('$'))
            .cloned()
            .collect::<Vec<_>>();
        (type_declarations, object_declarations)
    }

    pub fn exact_nested_object(
        &self,
        scala: &dyn ScalaSource,
        owner_fqn: &str,
        member: &str,
    ) -> Option<String> {
        self.exact_nested_object_unit(scala, owner_fqn, member)
            .map(|unit| unit.fq_name())
    }

    fn exact_nested_object_unit(
        &self,
        scala: &dyn ScalaSource,
        owner_fqn: &str,
        member: &str,
    ) -> Option<CodeUnit> {
        let candidate = format!("{owner_fqn}.{member}$");
        let mut matches = self
            .index
            .by_fqn(&candidate)
            .into_iter()
            .filter(|unit| unit.is_class() && self.type_accepts_object_roles(scala, unit));
        let resolved = matches.next()?;
        matches.next().is_none().then_some(resolved)
    }

    pub fn exact_nested_object_for_owner(
        &self,
        scala: &dyn ScalaSource,
        owner: &CodeUnit,
        member: &str,
    ) -> Option<CodeUnit> {
        let matches = self.exact_nested_objects_for_owner(scala, owner, member);
        let [resolved] = matches.as_slice() else {
            return None;
        };
        Some(resolved.clone())
    }

    /// The single nested object `member` names under `owner`, including one the
    /// owner inherits. More than one declaration at the first declaring
    /// template is ambiguous and resolves nothing.
    fn stable_nested_object_for_owner(
        &self,
        scala: &dyn ScalaSource,
        owner: &CodeUnit,
        member: &str,
    ) -> Option<CodeUnit> {
        let matches = self.stable_nested_objects_for_owner(scala, owner, member);
        let [resolved] = matches.as_slice() else {
            return None;
        };
        Some(resolved.clone())
    }

    fn exact_nested_objects_for_owner(
        &self,
        scala: &dyn ScalaSource,
        owner: &CodeUnit,
        member: &str,
    ) -> Vec<CodeUnit> {
        let candidate = format!("{}.{member}$", owner.fq_name());
        sorted_unique_units(
            self.index
                .by_fqn(&candidate)
                .iter()
                .filter(|unit| unit.is_class() && unit.source() == owner.source())
                .filter(|unit| self.is_exact_structural_child(scala, owner, unit))
                .cloned()
                .collect(),
        )
    }

    /// The nested objects `member` names under `owner`, reading the owner's own
    /// children first and its linearization second.
    ///
    /// A declared object inherits the nested objects of its parents, so
    /// `Holder.PersistNone` selects the `case object PersistNone` that `object
    /// Holder extends PersistentEntity` inherits (#2223). The direct-children
    /// read stays authoritative when it answers: an object's own declaration
    /// shadows an inherited one, and it alone carries the source and
    /// structural-child filters that distinguish physical replicas of the
    /// owner. The linearized read is the walk the wildcard-import binding and
    /// the type-projection member already use, so the first template that
    /// declares the name is the one it binds, and every declaration of the
    /// name at that tier is returned for the caller's ambiguity check. Like
    /// the direct read, it keeps only declared objects: a nested case class
    /// accepts object roles through its implicit companion, and recording it
    /// here would pre-empt the type-namespace resolution that owns its
    /// identity.
    ///
    /// An owner that accepts object roles only through an implicit companion
    /// declares no template of its own -- the parents in its `extends` clause
    /// belong to the class, not to the companion a stable selection reads --
    /// so there the direct children are the whole answer, exactly as in
    /// `wildcard_member_declarations`.
    fn stable_nested_objects_for_owner(
        &self,
        scala: &dyn ScalaSource,
        owner: &CodeUnit,
        member: &str,
    ) -> Vec<CodeUnit> {
        let exact = self.exact_nested_objects_for_owner(scala, owner, member);
        if !exact.is_empty() || !owner.short_name().ends_with('$') {
            return exact;
        }
        self.linearized_nested_declarations(
            scala,
            owner,
            HashSet::default(),
            |unit| {
                unit.is_class()
                    && unit.short_name().ends_with('$')
                    && self.type_accepts_object_roles(scala, unit)
            },
            scala_simple_type_name,
        )
        .into_iter()
        .filter(|(simple, _)| simple == member)
        .map(|(_, unit)| unit)
        .collect()
    }

    pub fn exact_nested_type(&self, owner_fqn: &str, member: &str) -> Option<String> {
        let candidate = format!("{owner_fqn}.{member}");
        let mut matches = self
            .index
            .by_fqn(&candidate)
            .into_iter()
            .filter(|unit| self.is_type_namespace_declaration(unit));
        let resolved = matches.next()?.fq_name();
        matches.next().is_none().then_some(resolved)
    }

    fn exact_nested_types_for_owner(
        &self,
        scala: &dyn ScalaSource,
        owner: &CodeUnit,
        member: &str,
    ) -> Vec<CodeUnit> {
        let candidate = format!("{}.{member}", owner.fq_name());
        sorted_unique_units(
            self.index
                .by_fqn(&candidate)
                .iter()
                .filter(|unit| {
                    self.is_type_namespace_declaration(unit) && unit.source() == owner.source()
                })
                .filter(|unit| self.is_exact_structural_child(scala, owner, unit))
                .cloned()
                .collect(),
        )
    }

    fn projected_nested_objects_for_owner(
        &self,
        parents: &HashMap<CodeUnit, CodeUnit>,
        owner: &CodeUnit,
        member: &str,
    ) -> Vec<CodeUnit> {
        let candidate = format!("{}.{member}$", owner.fq_name());
        sorted_unique_units(
            self.index
                .by_fqn(&candidate)
                .iter()
                .filter(|unit| unit.is_class() && unit.source() == owner.source())
                .filter(|unit| parents.get(*unit) == Some(owner))
                .cloned()
                .collect(),
        )
    }

    fn projected_nested_types_for_owner(
        &self,
        parents: &HashMap<CodeUnit, CodeUnit>,
        owner: &CodeUnit,
        member: &str,
    ) -> Vec<CodeUnit> {
        let candidate = format!("{}.{member}", owner.fq_name());
        sorted_unique_units(
            self.index
                .by_fqn(&candidate)
                .iter()
                .filter(|unit| {
                    self.is_type_namespace_declaration(unit) && unit.source() == owner.source()
                })
                .filter(|unit| parents.get(*unit) == Some(owner))
                .cloned()
                .collect(),
        )
    }

    fn resolve_type_text(&self, resolver: &NameResolver, type_text: &str) -> Option<String> {
        resolver
            .resolve(type_text)
            .or_else(|| {
                self.type_by_normalized_fqn(&scala_normalized_fq_name(type_text))
                    .map(|unit| unit.fq_name())
            })
            .or_else(|| scala_builtin_type_name(type_text).map(str::to_string))
    }

    fn type_lookup_path_is_ambiguous(&self, resolver: &NameResolver, segments: &[String]) -> bool {
        let Some(first) = segments.first() else {
            return false;
        };
        if resolver.type_binding_is_ambiguous(first) {
            return true;
        }
        let suffix = segments.join(".");
        resolver
            .package_prefixes
            .iter()
            .map(|package| {
                if package.is_empty() {
                    suffix.clone()
                } else {
                    format!("{package}.{suffix}")
                }
            })
            .chain(std::iter::once(suffix.clone()))
            .any(|candidate| {
                let normalized = scala_normalized_fq_name(&candidate);
                let candidates = self
                    .index
                    .by_normalized_fqn(&normalized)
                    .into_iter()
                    .filter(|unit| unit.is_class())
                    .collect::<Vec<_>>();
                let ordinary = candidates
                    .iter()
                    .filter(|unit| !unit.short_name().ends_with('$'))
                    .map(|unit| unit.fq_name())
                    .collect::<HashSet<_>>();
                if !ordinary.is_empty() {
                    ordinary.len() > 1
                } else {
                    candidates
                        .iter()
                        .map(|unit| unit.fq_name())
                        .collect::<HashSet<_>>()
                        .len()
                        > 1
                }
            })
    }

    pub fn resolve_type_in_declaration_context(
        &self,
        scala: &dyn ScalaSource,
        resolver: &NameResolver,
        segments: &[String],
    ) -> Option<String> {
        self.resolve_qualified_type_from_roots(
            resolver,
            segments,
            true,
            |owner, member| self.exact_nested_objects_for_owner(scala, owner, member),
            |owner, member| self.exact_nested_types_for_owner(scala, owner, member),
        )
    }

    pub fn resolve_type_in_hierarchy_context(
        &self,
        scala: &dyn ScalaSource,
        resolver: &NameResolver,
        segments: &[String],
    ) -> Option<String> {
        self.resolve_qualified_type_from_roots(
            resolver,
            segments,
            false,
            |owner, member| self.exact_nested_objects_for_owner(scala, owner, member),
            |owner, member| self.exact_nested_types_for_owner(scala, owner, member),
        )
    }

    fn resolve_type_in_projected_declaration_context(
        &self,
        resolver: &NameResolver,
        segments: &[String],
        parents: &HashMap<CodeUnit, CodeUnit>,
    ) -> Option<String> {
        self.resolve_qualified_type_from_roots(
            resolver,
            segments,
            false,
            |owner, member| self.projected_nested_objects_for_owner(parents, owner, member),
            |owner, member| self.projected_nested_types_for_owner(parents, owner, member),
        )
    }

    fn resolve_qualified_type_from_roots<ObjectChildren, TypeChildren>(
        &self,
        resolver: &NameResolver,
        segments: &[String],
        require_physical_terminal: bool,
        mut object_children: ObjectChildren,
        mut type_children: TypeChildren,
    ) -> Option<String>
    where
        ObjectChildren: FnMut(&CodeUnit, &str) -> Vec<CodeUnit>,
        TypeChildren: FnMut(&CodeUnit, &str) -> Vec<CodeUnit>,
    {
        let (first, rest) = segments.split_first()?;
        if first == "_root_" {
            if rest.is_empty() {
                return None;
            }
            let normalized = scala_normalized_fq_name(&rest.join("."));
            return if require_physical_terminal {
                self.unique_type_by_normalized_fqn(&normalized)
                    .map(|unit| unit.fq_name())
            } else {
                self.logical_type_by_normalized_fqn(&normalized)
            };
        }
        if rest.is_empty() {
            return (if require_physical_terminal {
                resolver.resolve(first)
            } else {
                resolver.resolve_logical(first)
            })
            .or_else(|| scala_builtin_type_name(first).map(str::to_string));
        }

        match resolver.resolve_qualified_type_root(self, first, Vec::new()) {
            ScalaQualifiedTypeRootResolution::Resolved(
                ScalaQualifiedTypeRootBinding::StableObjects(mut owners),
            ) => {
                for segment in &rest[..rest.len() - 1] {
                    owners = owners
                        .iter()
                        .flat_map(|owner| object_children(owner, segment))
                        .collect();
                    let mut seen = HashSet::default();
                    owners.retain(|owner| seen.insert(owner.clone()));
                }
                let terminal = rest.last()?;
                let mut matches = owners
                    .iter()
                    .flat_map(|owner| type_children(owner, terminal))
                    .collect::<Vec<_>>();
                if matches.is_empty() {
                    matches = owners
                        .iter()
                        .flat_map(|owner| object_children(owner, terminal))
                        .collect();
                }
                let mut seen = HashSet::default();
                matches.retain(|unit| seen.insert(unit.clone()));
                if require_physical_terminal {
                    let [resolved] = matches.as_slice() else {
                        return None;
                    };
                    return Some(resolved.fq_name());
                }
                let logical = matches
                    .iter()
                    .map(CodeUnit::fq_name)
                    .collect::<HashSet<_>>();
                return (logical.len() == 1)
                    .then(|| logical.into_iter().next())
                    .flatten();
            }
            ScalaQualifiedTypeRootResolution::Resolved(ScalaQualifiedTypeRootBinding::Package(
                package,
            )) => {
                let qualified = std::iter::once(package.as_str())
                    .chain(rest.iter().map(String::as_str))
                    .collect::<Vec<_>>()
                    .join(".");
                let normalized = scala_normalized_fq_name(&qualified);
                if require_physical_terminal {
                    return self
                        .unique_type_by_normalized_fqn(&normalized)
                        .map(|unit| unit.fq_name());
                }
                return self.logical_type_by_normalized_fqn(&normalized);
            }
            ScalaQualifiedTypeRootResolution::Ambiguous
            | ScalaQualifiedTypeRootResolution::AuthoritativeMiss => return None,
            ScalaQualifiedTypeRootResolution::NoMatch => {}
        }

        if resolver.has_type_or_object_or_package_binding(first)
            || !self.has_package_prefix(segments)
        {
            return None;
        }
        let qualified = segments.join(".");
        let normalized = scala_normalized_fq_name(&qualified);
        if require_physical_terminal {
            self.unique_type_by_normalized_fqn(&normalized)
                .map(|unit| unit.fq_name())
        } else {
            self.logical_type_by_normalized_fqn(&normalized)
        }
    }

    pub fn resolve_qualified_stable_type_at(
        &self,
        scala: &dyn ScalaSource,
        resolver: &NameResolver,
        segments: &[String],
        terminal_object: bool,
        lexical_root: Option<CodeUnit>,
    ) -> Option<String> {
        self.resolve_qualified_stable_type_unit_at(
            scala,
            resolver,
            segments,
            terminal_object,
            lexical_root,
        )
        .map(|unit| unit.fq_name())
    }

    pub fn resolve_qualified_stable_type_unit_at(
        &self,
        scala: &dyn ScalaSource,
        resolver: &NameResolver,
        segments: &[String],
        terminal_object: bool,
        lexical_root: Option<CodeUnit>,
    ) -> Option<CodeUnit> {
        self.resolve_qualified_stable_type_unit_at_with_lexical_roots(
            scala,
            resolver,
            segments,
            terminal_object,
            lexical_root.into_iter().collect(),
        )
    }

    pub fn resolve_qualified_stable_type_unit_at_with_lexical_roots(
        &self,
        scala: &dyn ScalaSource,
        resolver: &NameResolver,
        segments: &[String],
        terminal_object: bool,
        lexical_roots: Vec<CodeUnit>,
    ) -> Option<CodeUnit> {
        let (first, rest) = segments.split_first()?;
        if first == "_root_" {
            if rest.is_empty() {
                return None;
            }
            let normalized = scala_normalized_fq_name(&rest.join("."));
            return if terminal_object {
                self.unique_object_by_normalized_fqn(scala, &normalized)
            } else {
                self.unique_type_by_normalized_fqn(&normalized)
            };
        }
        if rest.is_empty() {
            let mut lexical_matches = lexical_roots
                .into_iter()
                .filter(|candidate| scala_simple_type_name(candidate) == *first)
                .filter(|candidate| {
                    if terminal_object {
                        self.type_accepts_object_roles(scala, candidate)
                    } else {
                        candidate.is_class() || self.is_type_alias(scala, candidate)
                    }
                })
                .collect::<Vec<_>>();
            lexical_matches.sort();
            lexical_matches.dedup();
            if let [resolved] = lexical_matches.as_slice() {
                return Some(resolved.clone());
            }
            if !lexical_matches.is_empty() {
                return None;
            }
            let fqn = if terminal_object {
                resolver.resolve_object(first)
            } else {
                resolver.resolve(first)
            }?;
            let normalized = scala_normalized_fq_name(&fqn);
            return if terminal_object {
                self.unique_object_by_normalized_fqn(scala, &normalized)
            } else {
                self.unique_type_by_normalized_fqn(&normalized)
            };
        }

        match resolver.resolve_qualified_type_root(self, first, lexical_roots) {
            ScalaQualifiedTypeRootResolution::Resolved(
                ScalaQualifiedTypeRootBinding::StableObjects(mut owners),
            ) => {
                for segment in &rest[..rest.len() - 1] {
                    owners = owners
                        .iter()
                        .flat_map(|owner| {
                            self.stable_nested_objects_for_owner(scala, owner, segment)
                        })
                        .collect();
                    let mut seen = HashSet::default();
                    owners.retain(|owner| seen.insert(owner.clone()));
                }
                let terminal = rest.last()?;
                let matches = owners
                    .iter()
                    .flat_map(|owner| {
                        if terminal_object {
                            self.stable_nested_objects_for_owner(scala, owner, terminal)
                        } else {
                            self.exact_nested_types_for_owner(scala, owner, terminal)
                        }
                    })
                    .collect::<Vec<_>>();
                let mut seen = HashSet::default();
                let matches = matches
                    .into_iter()
                    .filter(|unit| seen.insert(unit.clone()))
                    .collect::<Vec<_>>();
                let [resolved] = matches.as_slice() else {
                    return None;
                };
                return Some(resolved.clone());
            }
            ScalaQualifiedTypeRootResolution::Resolved(ScalaQualifiedTypeRootBinding::Package(
                package,
            )) => {
                let qualified = std::iter::once(package.as_str())
                    .chain(rest.iter().map(String::as_str))
                    .collect::<Vec<_>>()
                    .join(".");
                let normalized = scala_normalized_fq_name(&qualified);
                return if terminal_object {
                    self.unique_object_by_normalized_fqn(scala, &normalized)
                } else {
                    self.unique_type_by_normalized_fqn(&normalized)
                };
            }
            ScalaQualifiedTypeRootResolution::Ambiguous
            | ScalaQualifiedTypeRootResolution::AuthoritativeMiss => return None,
            ScalaQualifiedTypeRootResolution::NoMatch => {}
        }

        if resolver.has_type_or_object_or_package_binding(first)
            || !self.has_package_prefix(segments)
        {
            return None;
        }
        let normalized = scala_normalized_fq_name(&segments.join("."));
        if terminal_object {
            return self.unique_object_by_normalized_fqn(scala, &normalized);
        }
        self.unique_type_by_normalized_fqn(&normalized)
    }

    fn resolve_type_in_callable_declaration_context(
        &self,
        scala: &dyn ScalaSource,
        resolver: &NameResolver,
        declaration: &CodeUnit,
        segments: &[String],
    ) -> Option<String> {
        let (first, rest) = segments.split_first()?;
        let mut scope = self.declaration_parent(scala, declaration);
        let mut seen = HashSet::default();
        while let Some(owner) = scope {
            if !seen.insert(owner.clone()) {
                break;
            }
            let lexical_root = (owner.is_class() && scala_simple_type_name(&owner) == *first)
                .then(|| {
                    self.type_by_normalized_fqn(&scala_normalized_fq_name(&owner.fq_name()))
                        .map(|unit| unit.fq_name())
                })
                .flatten()
                .or_else(|| self.exact_nested_type(&owner.fq_name(), first));
            if let Some(mut resolved) = lexical_root {
                let mut complete = true;
                for segment in rest {
                    let candidate = format!("{resolved}.{segment}");
                    let declarations = self.index.by_fqn(&candidate);
                    let Some(nested) =
                        preferred_scala_type(declarations.iter().filter(|unit| unit.is_class()))
                    else {
                        complete = false;
                        break;
                    };
                    resolved = nested.fq_name();
                }
                if complete {
                    return Some(resolved);
                }
            }
            scope = self.declaration_parent(scala, &owner);
        }
        self.resolve_type_in_declaration_context(scala, resolver, segments)
    }

    fn resolve_type_in_owner_context(
        &self,
        resolver: &NameResolver,
        segments: &[String],
        owner: &CodeUnit,
        state: &ScalaFileFacts,
        parent_by_child: &HashMap<&CodeUnit, &CodeUnit>,
        projected_parent_by_unit: &HashMap<CodeUnit, CodeUnit>,
    ) -> Option<String> {
        let (first, rest) = segments.split_first()?;
        let mut scope = parent_by_child.get(owner).copied();
        while let Some(parent) = scope {
            let lexical = state
                .children
                .get(parent)
                .into_iter()
                .flatten()
                .filter(|unit| unit.is_class() && scala_simple_type_name(unit) == *first)
                .collect::<Vec<_>>();
            if !lexical.is_empty() {
                let ordinary = lexical
                    .iter()
                    .copied()
                    .filter(|unit| !unit.short_name().ends_with('$'))
                    .map(CodeUnit::fq_name)
                    .collect::<HashSet<_>>();
                let candidates = if ordinary.is_empty() {
                    lexical.into_iter().map(CodeUnit::fq_name).collect()
                } else {
                    ordinary
                };
                return (candidates.len() == 1)
                    .then(|| self.resolve_nested_type_segments(candidates, rest))
                    .flatten();
            }
            scope = parent_by_child.get(parent).copied();
        }
        if resolver.has_type_or_object_binding(first) {
            return self.resolve_type_in_projected_declaration_context(
                resolver,
                segments,
                projected_parent_by_unit,
            );
        }
        if let Some(relative) = self.resolve_package_relative_type(&state.package_name, segments) {
            return Some(relative);
        }
        self.resolve_type_in_projected_declaration_context(
            resolver,
            segments,
            projected_parent_by_unit,
        )
    }

    fn resolve_package_relative_type(
        &self,
        package_name: &str,
        segments: &[String],
    ) -> Option<String> {
        if package_name.is_empty() || segments.is_empty() {
            return None;
        }
        let normalized =
            scala_normalized_fq_name(&format!("{package_name}.{}", segments.join(".")));
        let candidates = self
            .index
            .by_normalized_fqn(&normalized)
            .into_iter()
            .filter(|unit| unit.is_class())
            .collect::<Vec<_>>();
        let ordinary = candidates
            .iter()
            .filter(|unit| !unit.short_name().ends_with('$'))
            .cloned()
            .collect::<Vec<_>>();
        let preferred = if ordinary.is_empty() {
            candidates
        } else {
            ordinary
        };
        (preferred.len() == 1).then(|| preferred[0].fq_name())
    }

    fn resolve_nested_type_segments(
        &self,
        mut candidates: HashSet<String>,
        segments: &[String],
    ) -> Option<String> {
        for segment in segments {
            let mut nested_candidates = HashSet::default();
            for owner in candidates {
                for candidate in [format!("{owner}.{segment}"), format!("{owner}.{segment}$")] {
                    nested_candidates.extend(
                        self.index
                            .by_fqn(&candidate)
                            .iter()
                            .filter(|unit| unit.is_class())
                            .map(CodeUnit::fq_name),
                    );
                }
            }
            if nested_candidates.is_empty() {
                return None;
            }
            candidates = nested_candidates;
        }
        (candidates.len() == 1)
            .then(|| candidates.into_iter().next())
            .flatten()
    }

    fn has_package_prefix(&self, segments: &[String]) -> bool {
        (1..segments.len()).any(|end| self.index.package_exists(&segments[..end].join(".")))
    }

    fn package_objects_in(&self, scala: &dyn ScalaSource, package: &str) -> PackageTypeEntries {
        if let Some(objects) = self
            .package_objects_by_package
            .lock()
            .expect("package object cache poisoned")
            .get(package)
            .cloned()
        {
            return objects;
        }

        let mut values = Vec::new();
        for (simple, units) in self.index.package_types_in(package) {
            let exact = units
                .iter()
                .filter(|unit| {
                    unit.is_class()
                        && is_package_level_type(unit)
                        && unit.short_name().ends_with('$')
                })
                .collect::<Vec<_>>();
            if !exact.is_empty() {
                for unit in exact {
                    values.push((simple.clone(), unit.clone()));
                }
                continue;
            }
            for unit in units.iter().filter(|unit| {
                unit.is_class()
                    && is_package_level_type(unit)
                    && self.type_accepts_object_roles(scala, unit)
            }) {
                values.push((simple.clone(), unit.clone()));
            }
        }
        let values = Arc::new(values);
        self.package_objects_by_package
            .lock()
            .expect("package object cache poisoned")
            .insert(package.to_string(), values.clone());
        values
    }

    /// The nested declarations a wildcard import of `owner` binds, paired with
    /// the name each one binds, in the namespace `accepts` and `visible_name`
    /// select.
    ///
    /// Scala makes an inherited nested declaration a member of the importing
    /// singleton, so the search runs over the owner's linearization and not
    /// over its own children alone. specs2 writes `trait EditDistance:` with
    /// `case class Add[T](t: T)` and `def levenhsteinDistance` inside it, and
    /// declares `object EditDistance extends EditDistance` beside it; `import
    /// EditDistance.*` binds both names, and a lookup that reads only the
    /// object's own children sees neither. The first template in the
    /// linearization that declares a name is the one that name binds, so a
    /// nearer declaration shadows an inherited one. `bound` carries the names
    /// the owner already binds outside its own children, so those shadow an
    /// inherited declaration in the same way a directly declared one does.
    fn linearized_nested_declarations(
        &self,
        scala: &dyn ScalaSource,
        owner: &CodeUnit,
        mut bound: HashSet<String>,
        accepts: impl Fn(&CodeUnit) -> bool,
        visible_name: impl Fn(&CodeUnit) -> String,
    ) -> Vec<(String, CodeUnit)> {
        let mut declarations = Vec::new();
        for template in self.linearized_owners(scala, owner) {
            let mut declared: HashMap<String, Vec<CodeUnit>> = HashMap::default();
            for unit in self
                .index
                .fqn_direct_children(&template.fq_name())
                .into_iter()
                .filter(&accepts)
            {
                declared.entry(visible_name(&unit)).or_default().push(unit);
            }
            for (simple, units) in declared {
                if !bound.insert(simple.clone()) {
                    continue;
                }
                declarations.extend(units.into_iter().map(|unit| (simple.clone(), unit)));
            }
        }
        declarations
    }

    /// The term members a wildcard import of `owner` binds, paired with the
    /// name each one binds.
    ///
    /// A declared `object` inherits its parents' term members, so specs2's
    /// `import EditDistance.*` binds `levenhsteinDistance`: `trait
    /// EditDistance` declares it and `object EditDistance extends EditDistance`
    /// inherits it. An owner that accepts object roles only through an implicit
    /// companion declares no template of its own -- the parents in the
    /// `extends` clause belong to the case class, not to the companion a
    /// wildcard import reads -- so there its own children are the whole
    /// binding.
    ///
    /// An export alias is a declaration of the exporting object and therefore
    /// shadows an inherited member of the same name. The caller adds the
    /// aliases themselves; this reports only the declarations they leave
    /// visible.
    ///
    /// Shared with the forward resolver in `brokk-bifrost-analysis`, whose
    /// wildcard-imported-member lookup binds the same members (#2212); the
    /// linearization walk is not re-derived there.
    pub fn wildcard_member_declarations(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        owner: &CodeUnit,
    ) -> PackageTypeEntries {
        let owner_fqn = owner.fq_name();
        if let Some(members) = self
            .wildcard_members_by_owner
            .lock()
            .expect("Scala wildcard member cache poisoned")
            .get(&owner_fqn)
            .cloned()
        {
            return members;
        }
        let accepts = |unit: &CodeUnit| unit.is_function() || unit.is_field();
        let members = if owner.short_name().ends_with('$') {
            // `exported_member_bindings` reports the owner's whole visible term
            // surface, its own children included, so the shadow seed is the
            // aliases alone: the linearization's first template contributes the
            // owner's own children and pre-seeding their names would drop them.
            let declared = self.direct_member_bindings(&owner_fqn);
            let aliases = self
                .exported_member_bindings(scala, token, owner)
                .into_iter()
                .map(|(visible_name, _)| visible_name)
                .filter(|visible_name| !declared.contains_key(visible_name))
                .collect();
            self.linearized_nested_declarations(scala, owner, aliases, accepts, |unit| {
                scala_short_name_terminal_segment(unit.short_name())
            })
        } else {
            self.index
                .fqn_direct_children(&owner_fqn)
                .into_iter()
                .filter(accepts)
                .map(|unit| (scala_short_name_terminal_segment(unit.short_name()), unit))
                .collect()
        };
        let members = Arc::new(members);
        self.wildcard_members_by_owner
            .lock()
            .expect("Scala wildcard member cache poisoned")
            .insert(owner_fqn, members.clone());
        members
    }

    /// The declaration a type projection `Owner#Member` names.
    ///
    /// `#` selects a type member of the type on its left, so the lookup is the
    /// linearization walk the type namespace already uses: the first template
    /// that declares the name is the one the projection binds, and a nearer
    /// declaration therefore shadows an inherited one. More than one
    /// declaration of the name at that tier is ambiguous and binds nothing.
    pub fn projected_type_member(
        &self,
        scala: &dyn ScalaSource,
        owner: &CodeUnit,
        member: &str,
    ) -> Option<CodeUnit> {
        let mut matches = self
            .linearized_nested_declarations(
                scala,
                owner,
                HashSet::default(),
                |unit| self.is_type_namespace_declaration(unit),
                scala_simple_type_name,
            )
            .into_iter()
            .filter(|(simple, _)| simple == member)
            .map(|(_, unit)| unit);
        let resolved = matches.next()?;
        matches.next().is_none().then_some(resolved)
    }

    fn nested_types_in(
        &self,
        scala: &dyn ScalaSource,
        normalized_owner: &str,
    ) -> PackageTypeEntries {
        if let Some(types) = self
            .nested_types_by_owner
            .lock()
            .expect("nested Scala type cache poisoned")
            .get(normalized_owner)
            .cloned()
        {
            return types;
        }
        let mut grouped: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        for owner in self
            .index
            .by_normalized_fqn(normalized_owner)
            .iter()
            .filter(|unit| unit.is_class() && self.type_is_stable_owner(scala, unit))
        {
            for (simple, unit) in self.linearized_nested_declarations(
                scala,
                owner,
                HashSet::default(),
                |unit| self.is_type_namespace_declaration(unit),
                scala_simple_type_name,
            ) {
                grouped.entry(simple).or_default().push(unit);
            }
        }
        let mut values = Vec::new();
        for (simple, units) in grouped {
            let ordinary = units
                .iter()
                .filter(|unit| {
                    self.type_aliases.contains(*unit) || !unit.short_name().ends_with('$')
                })
                .collect::<Vec<_>>();
            let selected = if ordinary.is_empty() {
                units.iter().collect::<Vec<_>>()
            } else {
                ordinary
            };
            values.extend(
                selected
                    .into_iter()
                    .map(|unit| (simple.clone(), unit.clone())),
            );
        }
        let values = Arc::new(values);
        self.nested_types_by_owner
            .lock()
            .expect("nested Scala type cache poisoned")
            .insert(normalized_owner.to_string(), values.clone());
        values
    }

    fn nested_objects_in(
        &self,
        scala: &dyn ScalaSource,
        normalized_owner: &str,
    ) -> PackageTypeEntries {
        if let Some(types) = self
            .nested_objects_by_owner
            .lock()
            .expect("nested Scala object cache poisoned")
            .get(normalized_owner)
            .cloned()
        {
            return types;
        }
        let mut grouped: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        for owner in self
            .index
            .by_normalized_fqn(normalized_owner)
            .iter()
            .filter(|unit| unit.is_class() && self.type_is_stable_owner(scala, unit))
        {
            for (simple, unit) in self.linearized_nested_declarations(
                scala,
                owner,
                HashSet::default(),
                |unit| unit.is_class() && self.type_accepts_object_roles(scala, unit),
                scala_simple_type_name,
            ) {
                grouped.entry(simple).or_default().push(unit);
            }
        }
        // A declared companion object is the object this name binds. A case
        // class beside it accepts object roles through its implicit companion,
        // and counting both would make `object O { case class G(..); object G
        // { .. } }` an ambiguous binding for `G` -- the same rule
        // `package_objects_in` applies at package level.
        let mut values = Vec::new();
        for (simple, units) in grouped {
            let declared = units
                .iter()
                .filter(|unit| unit.short_name().ends_with('$'))
                .cloned()
                .collect::<Vec<_>>();
            let selected = if declared.is_empty() { units } else { declared };
            for unit in selected {
                values.push((simple.clone(), unit));
            }
        }
        let values = Arc::new(values);
        self.nested_objects_by_owner
            .lock()
            .expect("nested Scala object cache poisoned")
            .insert(normalized_owner.to_string(), values.clone());
        values
    }

    fn importable_members_by_normalized_fqn(
        &self,
        scala: &dyn ScalaSource,
        normalized_fqn: &str,
        source_file: Option<&ProjectFile>,
    ) -> Vec<CodeUnit> {
        let declarations = self.index.by_normalized_fqn(normalized_fqn);
        let candidates = declarations
            .iter()
            .filter(|unit| unit.is_function() || self.has_term_field_declaration(unit))
            .collect::<Vec<_>>();
        if let [candidate] = candidates.as_slice() {
            return vec![(*candidate).clone()];
        }
        if candidates.iter().any(|unit| unit.is_function()) {
            // A same-file overload family is one importable declaration split
            // into per-overload units (#1327), and a coherent replica family is
            // one importable declaration cross-built across source sets
            // (#2021); either way the selector names one logical declaration
            // and every member unit is contributed. A candidate set that
            // disagrees on an identity field is a genuine collision and still
            // yields nothing.
            return if single_replica_family(candidates.iter().copied()) {
                candidates.into_iter().cloned().collect()
            } else {
                Vec::new()
            };
        }
        let Some(source_file) = source_file else {
            return Vec::new();
        };
        let stable_members = candidates
            .into_iter()
            .filter(|unit| self.has_term_field_declaration(unit))
            .filter(|unit| unit.source() == source_file)
            .filter(|unit| {
                self.exact_structural_parent(scala, unit)
                    .is_some_and(|owner| {
                        owner.source() == source_file
                            && owner.is_class()
                            && owner.short_name().ends_with('$')
                            && self.type_is_stable_owner(scala, &owner)
                    })
            })
            .collect::<Vec<_>>();
        let [candidate] = stable_members.as_slice() else {
            return Vec::new();
        };
        vec![(*candidate).clone()]
    }

    fn exact_field(
        &self,
        _scala: &dyn ScalaSource,
        owner_fqn: &str,
        member: &str,
    ) -> Option<CodeUnit> {
        let field_fqn = format!("{owner_fqn}.{member}");
        let fields = self
            .index
            .by_fqn(&field_fqn)
            .into_iter()
            .filter(|unit| self.has_term_field_declaration(unit))
            .collect::<Vec<_>>();
        (fields.len() == 1).then(|| fields[0].clone())
    }

    pub fn constructor_target_matches(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        target: &CodeUnit,
        call_shape: Option<&ScalaCallSiteShape>,
        site_role: ScalaCallableSiteRole,
    ) -> bool {
        let alternatives = self.callable_alternatives_for(scala, token, target);
        if alternatives.is_empty() {
            return scala_callable_alternative_matches(
                ScalaCallableRole::PrimaryConstructor,
                &[ScalaCallableParameterList::explicit(CallableArity::exact(
                    0,
                ))],
                ScalaDeclaredResult::UNDECLARED,
                call_shape,
                site_role,
                false,
            );
        }
        alternatives.iter().any(|alternative| {
            scala_callable_alternative_matches(
                alternative.role,
                &alternative.shape,
                alternative.result,
                call_shape,
                site_role,
                false,
            )
        })
    }

    pub fn callable_alternatives_for(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        target: &CodeUnit,
    ) -> CachedCallableAlternatives {
        let cell = self
            .callable_alternatives_by_unit
            .lock()
            .expect("Scala callable-alternative cache poisoned")
            .entry(target.clone())
            .or_insert_with(|| Arc::new(OnceLock::new()))
            .clone();
        cell.get_or_init(|| {
            let source_facts = self.source_facts_for_file(scala, target.source());
            let declaration_resolver = NameResolver::for_file_types(scala, token, target, self);
            let ranges = self.declaration_ranges_for(scala, target);
            let mut exact = ranges
                .iter()
                .filter_map(|range| {
                    source_facts
                        .callable_alternatives_by_range
                        .get(&(range.start_byte, range.end_byte))
                        .map(|facts| {
                            let generic_type_parameters = source_facts
                                .generic_owner_facts_by_range
                                .get(&(range.start_byte, range.end_byte))
                                .map(|facts| facts.type_parameters.as_slice())
                                .unwrap_or_default();
                            CallableAlternative {
                            role: facts.role,
                            shape: facts.shape.clone(),
                            result: facts.result,
                            parameter_defaults: facts.parameter_defaults.clone(),
                            parameter_types: facts
                                .parameter_type_paths
                                .iter()
                                .map(|parameters| {
                                    parameters
                                        .iter()
                                        .map(|path| {
                                            path.as_deref().and_then(|path| {
                                                self.resolve_callable_parameter_type_identity(
                                                    scala,
                                                    &declaration_resolver,
                                                    target,
                                                    path,
                                                    generic_type_parameters,
                                                )
                                            })
                                        })
                                        .collect()
                                })
                                .collect(),
                            parameter_function_shapes: facts
                                .parameter_function_arities
                                .iter()
                                .zip(&facts.parameter_function_type_paths)
                                .map(|(arities, parameter_paths)| {
                                    arities
                                        .iter()
                                        .zip(parameter_paths)
                                        .map(|(arity, paths)| {
                                            let arity = (*arity)?;
                                            let parameter_types =
                                                paths.as_ref().and_then(|paths| {
                                                    paths
                                                        .iter()
                                                        .map(|path| {
                                                            path.as_deref().and_then(|path| {
                                                                self.resolve_callable_parameter_type_identity(
                                                                    scala,
                                                                    &declaration_resolver,
                                                                    target,
                                                                    path,
                                                                    generic_type_parameters,
                                                                )
                                                            })
                                                        })
                                                        .collect::<Option<Vec<_>>>()
                                                });
                                            let parameter_types_authoritative = parameter_types
                                                .as_ref()
                                                .is_none_or(|types| {
                                                    !types.iter().any(|identity| {
                                                        matches!(
                                                            identity,
                                                            ScalaParameterTypeIdentity::TypeParameter(_)
                                                                | ScalaParameterTypeIdentity::Unresolved(_)
                                                        )
                                                    })
                                                })
                                                && paths.as_ref().is_some_and(|paths| {
                                                    paths.iter().all(Option::is_some)
                                                });
                                            Some(ScalaFunctionParameterShape {
                                                arity,
                                                parameter_types,
                                                parameter_types_authoritative,
                                            })
                                        })
                                        .collect()
                                })
                                .collect(),
                            extension_receiver_type: facts
                                .extension_receiver_type_path
                                .as_deref()
                                .and_then(|segments| {
                                    self.resolve_type_in_callable_declaration_context(
                                        scala,
                                        &declaration_resolver,
                                        target,
                                        segments,
                                    )
                                }),
                            return_type: facts.return_type_path.as_deref().and_then(|segments| {
                                self.resolve_type_in_callable_declaration_context(
                                    scala,
                                    &declaration_resolver,
                                    target,
                                        segments,
                                    )
                                }),
                            }
                        })
                })
                .collect::<Vec<_>>();
            if let Some(case_class) = self.exact_case_class_for_companion_apply(scala, target) {
                for constructor in self.callable_alternatives_for(scala, token, &case_class).iter() {
                    if exact
                        .iter()
                        .any(|alternative| alternative.shape == constructor.shape)
                    {
                        continue;
                    }
                    let mut synthetic = constructor.clone();
                    synthetic.role = ScalaCallableRole::Ordinary;
                    synthetic.extension_receiver_type = None;
                    synthetic.return_type = Some(case_class.fq_name());
                    exact.push(synthetic);
                }
            }
            if !exact.is_empty() {
                return Arc::new(exact);
            }
            let mut fallback = self
                .signature_metadata_for(scala, target)
                .into_iter()
                .filter_map(|metadata| {
                    metadata.callable_arity().map(|arity| CallableAlternative {
                        role: if target.is_synthetic() {
                            ScalaCallableRole::PrimaryConstructor
                        } else {
                            ScalaCallableRole::Ordinary
                        },
                        shape: vec![ScalaCallableParameterList::explicit(arity)],
                        // A signature-only fallback carries no declared result,
                        // so nothing beyond its parameter list is admitted.
                        result: ScalaDeclaredResult::UNDECLARED,
                        parameter_defaults: Vec::new(),
                        parameter_types: Vec::new(),
                        parameter_function_shapes: Vec::new(),
                        extension_receiver_type: None,
                        return_type: None,
                    })
                })
                .collect::<Vec<_>>();
            if fallback.is_empty()
                && let Some(arity) = self.callable_facts(scala, token, target).and_then(|facts| {
                    facts
                        .callable_arity
                        .or_else(|| facts.arity.map(CallableArity::exact))
                })
            {
                fallback.push(CallableAlternative {
                    role: if target.is_synthetic() {
                        ScalaCallableRole::PrimaryConstructor
                    } else {
                        ScalaCallableRole::Ordinary
                    },
                    shape: vec![ScalaCallableParameterList::explicit(arity)],
                    result: ScalaDeclaredResult::UNDECLARED,
                    parameter_defaults: Vec::new(),
                    parameter_types: Vec::new(),
                    parameter_function_shapes: Vec::new(),
                    extension_receiver_type: None,
                    return_type: self
                        .callable_facts(scala, token, target)
                        .and_then(|facts| facts.return_type_fqn.clone()),
                });
            }
            Arc::new(fallback)
        })
        .clone()
    }

    /// Return the source-declared callable alternatives with default parameters
    /// inherited by exact override families applied to the concrete declaration.
    ///
    /// Scala dispatches a call to an override even when the omitted argument's
    /// default is declared only by an ancestor.  We preserve that concrete
    /// target, but merge defaults only when every parameter position has an
    /// exact, source-backed type identity and the hierarchy itself is
    /// unambiguous.
    pub fn effective_callable_alternatives_for(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        target: &CodeUnit,
    ) -> CachedCallableAlternatives {
        let cell = self
            .effective_callable_alternatives_by_unit
            .lock()
            .expect("Scala effective callable-alternative cache poisoned")
            .entry(target.clone())
            .or_insert_with(|| Arc::new(OnceLock::new()))
            .clone();
        cell.get_or_init(|| {
            let declared = self.callable_alternatives_for(scala, token, target);
            let Some(owner) = self.exact_structural_parent(scala, target) else {
                return declared;
            };
            if !target.is_function()
                || declared.is_empty()
                || !self.hierarchy_is_unambiguous(scala, token, &owner)
            {
                return declared;
            }

            let linearized = self.linearized_owners(scala, &owner);
            if linearized.first() != Some(&owner) {
                return declared;
            }
            let mut effective = declared.as_ref().clone();
            for alternative in &mut effective {
                if alternative.role != ScalaCallableRole::Ordinary
                    || alternative.parameter_defaults.len() != alternative.shape.len()
                    || alternative.parameter_types.len() != alternative.shape.len()
                {
                    continue;
                }
                let declared_alternative = alternative.clone();
                let Some(defaults) = self.inherited_default_mask_for_alternative(
                    scala,
                    token,
                    &linearized[1..],
                    target.identifier(),
                    &declared_alternative,
                ) else {
                    continue;
                };
                alternative.parameter_defaults = defaults;
                apply_parameter_defaults_to_shape(alternative);
            }
            Arc::new(effective)
        })
        .clone()
    }

    fn hierarchy_is_unambiguous(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        root: &CodeUnit,
    ) -> bool {
        let mut pending = vec![root.clone()];
        let mut seen = HashSet::default();
        while let Some(owner) = pending.pop() {
            if !seen.insert(owner.clone()) {
                continue;
            }
            match self.exact_direct_ancestor_resolution(scala, token, &owner) {
                ScalaDirectAncestorResolution::Resolved(ancestors)
                | ScalaDirectAncestorResolution::Incomplete(ancestors) => pending.extend(ancestors),
                ScalaDirectAncestorResolution::Ambiguous => return false,
            }
        }
        true
    }

    fn inherited_default_mask_for_alternative(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        ancestors: &[CodeUnit],
        member: &str,
        declared: &CallableAlternative,
    ) -> Option<Vec<Vec<bool>>> {
        let mut defaults = declared.parameter_defaults.clone();
        let mut inherited = Vec::new();
        for owner in ancestors {
            let mut exact = Vec::new();
            let mut unknown = false;
            for method in self
                .members_for_exact_owner_unit(scala, owner, member)
                .into_iter()
                .filter(|unit| unit.is_function())
            {
                for alternative in self.callable_alternatives_for(scala, token, &method).iter() {
                    match override_family_relation(declared, alternative) {
                        OverrideFamilyRelation::Exact => exact.push(alternative.clone()),
                        OverrideFamilyRelation::Unknown => unknown = true,
                        OverrideFamilyRelation::Different => {}
                    }
                }
            }
            if unknown || exact.len() > 1 {
                return None;
            }
            let Some(ancestor) = exact.pop() else {
                continue;
            };
            inherited.push((owner.clone(), ancestor));
        }
        for (index, (left, _)) in inherited.iter().enumerate() {
            for (right, _) in &inherited[index + 1..] {
                if !self.exact_owner_inherits(scala, token, left, right)
                    && !self.exact_owner_inherits(scala, token, right, left)
                {
                    return None;
                }
            }
        }
        for (_, ancestor) in inherited {
            if ancestor.parameter_defaults.len() != defaults.len() {
                return None;
            }
            for (effective_list, inherited_list) in
                defaults.iter_mut().zip(&ancestor.parameter_defaults)
            {
                if effective_list.len() != inherited_list.len() {
                    return None;
                }
                for (effective, inherited) in effective_list.iter_mut().zip(inherited_list) {
                    *effective |= *inherited;
                }
            }
        }
        Some(defaults)
    }

    fn resolve_callable_parameter_type_identity(
        &self,
        scala: &dyn ScalaSource,
        resolver: &NameResolver,
        declaration: &CodeUnit,
        path: &[String],
        generic_type_parameters: &[String],
    ) -> Option<ScalaParameterTypeIdentity> {
        if let Some(declaration) =
            self.resolve_callable_parameter_type_unit(scala, resolver, declaration, path)
        {
            return Some(ScalaParameterTypeIdentity::Declaration(declaration));
        }
        let [simple] = path else {
            return None;
        };
        if generic_type_parameters.contains(simple) {
            return Some(ScalaParameterTypeIdentity::TypeParameter(simple.clone()));
        }
        let builtin = scala_builtin_type_name(simple);
        let logical_candidates = resolver.logical_type_import_candidates(simple);
        let explicit_logical_import = resolver.has_explicit_logical_type_import(simple);
        if (builtin.is_none() || explicit_logical_import)
            && !logical_candidates.is_empty()
            && logical_candidates.iter().all(|logical| {
                self.index
                    .by_normalized_fqn(&scala_normalized_fq_name(logical))
                    .is_empty()
            })
        {
            return Some(match logical_candidates.as_slice() {
                [logical] => ScalaParameterTypeIdentity::Logical(logical.clone()),
                _ => ScalaParameterTypeIdentity::LogicalCandidates(logical_candidates),
            });
        }
        if resolver.has_type_or_object_or_package_binding(simple) {
            return None;
        }
        Some(
            builtin
                .map(ScalaParameterTypeIdentity::Builtin)
                .unwrap_or_else(|| ScalaParameterTypeIdentity::Unresolved(path.to_vec())),
        )
    }

    fn resolve_callable_parameter_type_unit(
        &self,
        scala: &dyn ScalaSource,
        resolver: &NameResolver,
        declaration: &CodeUnit,
        path: &[String],
    ) -> Option<CodeUnit> {
        let (first, rest) = path.split_first()?;
        if rest.is_empty() {
            let fqn = resolver.resolve(first)?;
            let candidates = self
                .index
                .by_fqn(&fqn)
                .iter()
                .filter(|unit| unit.is_class() && !unit.short_name().ends_with('$'))
                .cloned()
                .collect::<Vec<_>>();
            let same_source = candidates
                .iter()
                .filter(|unit| unit.source() == declaration.source())
                .cloned()
                .collect::<Vec<_>>();
            return match same_source.as_slice() {
                [exact] => Some(exact.clone()),
                [] => match candidates.as_slice() {
                    [exact] => Some(exact.clone()),
                    _ => None,
                },
                _ => None,
            };
        }

        let mut scope = self.declaration_parent(scala, declaration);
        let mut seen = HashSet::default();
        while let Some(owner) = scope {
            if !seen.insert(owner.clone()) {
                break;
            }
            let mut roots = self.exact_nested_objects_for_owner(scala, &owner, first);
            roots.extend(self.exact_nested_types_for_owner(scala, &owner, first));
            roots.sort();
            roots.dedup();
            if let [root] = roots.as_slice() {
                let mut owners = vec![root.clone()];
                for segment in &rest[..rest.len() - 1] {
                    owners = owners
                        .iter()
                        .flat_map(|owner| {
                            self.exact_nested_objects_for_owner(scala, owner, segment)
                        })
                        .collect();
                    owners.sort();
                    owners.dedup();
                    if owners.len() != 1 {
                        break;
                    }
                }
                if owners.len() == 1 {
                    let terminal = rest.last()?;
                    let mut matches =
                        self.exact_nested_types_for_owner(scala, &owners[0], terminal);
                    matches.sort();
                    matches.dedup();
                    if let [exact] = matches.as_slice() {
                        return Some(exact.clone());
                    }
                }
            } else if !roots.is_empty() {
                return None;
            }
            scope = self.declaration_parent(scala, &owner);
        }

        for candidate in scala_enclosing_package_root_candidates(&resolver.package_prefixes, first)
        {
            if self.index.package_exists(&candidate) {
                continue;
            }
            let normalized = scala_normalized_fq_name(&candidate);
            let Some(root) = self.unique_object_by_normalized_fqn(scala, &normalized) else {
                continue;
            };
            if let Some(resolved) =
                self.resolve_qualified_stable_type_unit_at(scala, resolver, path, false, Some(root))
            {
                return Some(resolved);
            }
        }
        self.resolve_qualified_stable_type_unit_at(scala, resolver, path, false, None)
    }

    pub fn exact_case_class_for_companion_apply(
        &self,
        scala: &dyn ScalaSource,
        target: &CodeUnit,
    ) -> Option<CodeUnit> {
        if !target.is_function()
            || scala_short_name_terminal_segment(target.short_name()) != "apply"
        {
            return None;
        }
        let companion = self.exact_structural_parent(scala, target)?;
        if !companion.is_class() || !companion.short_name().ends_with('$') {
            return None;
        }
        let structural_parent = self.exact_structural_parent(scala, &companion);
        let mut candidates = self
            .index
            .by_normalized_fqn(&scala_normalized_fq_name(&companion.fq_name()))
            .into_iter()
            .filter(|candidate| {
                candidate.is_class()
                    && !candidate.short_name().ends_with('$')
                    && candidate.source() == companion.source()
                    && self.exact_structural_parent(scala, candidate) == structural_parent
                    && self.is_case_class(scala, candidate)
            });
        let candidate = candidates.next()?;
        candidates.next().is_none().then_some(candidate)
    }

    pub fn type_accepts_object_roles(&self, scala: &dyn ScalaSource, target: &CodeUnit) -> bool {
        if self.type_is_stable_owner(scala, target) {
            return true;
        }
        let source_facts = self.source_facts_for_file(scala, target.source());
        self.declaration_ranges_for(scala, target)
            .iter()
            .any(|range| {
                source_facts
                    .case_class_ranges
                    .contains(&(range.start_byte, range.end_byte))
            })
    }

    pub fn type_is_stable_owner(&self, scala: &dyn ScalaSource, target: &CodeUnit) -> bool {
        if target.short_name().ends_with('$') {
            return true;
        }
        let source_facts = self.source_facts_for_file(scala, target.source());
        self.declaration_ranges_for(scala, target)
            .iter()
            .any(|range| {
                source_facts
                    .stable_owner_ranges
                    .contains(&(range.start_byte, range.end_byte))
            })
    }

    pub fn stable_roots_for_resolved_type_name(
        &self,
        scala: &dyn ScalaSource,
        resolver: &NameResolver,
        name: &str,
    ) -> Vec<CodeUnit> {
        let Some(fqn) = resolver.resolve(name) else {
            return Vec::new();
        };
        let Some(declaration) = self.unique_type_by_normalized_fqn(&scala_normalized_fq_name(&fqn))
        else {
            return Vec::new();
        };
        // This bridge exists only for stable *type* roots such as enums. A
        // standalone object must stay in the term namespace so the resolver
        // can detect same-priority package/object alias collisions.
        if declaration.short_name().ends_with('$') {
            return Vec::new();
        }
        let mut roots = self.exact_companion_objects(scala, &declaration);
        if self.type_is_stable_owner(scala, &declaration) {
            roots.push(declaration);
        }
        roots.sort();
        roots.dedup();
        roots
    }

    pub fn exact_companion_objects(
        &self,
        scala: &dyn ScalaSource,
        target: &CodeUnit,
    ) -> Vec<CodeUnit> {
        let target_parent = self.exact_structural_parent(scala, target);
        self.index
            .by_normalized_fqn(&scala_normalized_fq_name(&target.fq_name()))
            .iter()
            .filter(|candidate| {
                candidate.is_class()
                    && *candidate != target
                    && candidate.source() == target.source()
                    && candidate.short_name().ends_with('$')
                    && self.exact_structural_parent(scala, candidate) == target_parent
            })
            .cloned()
            .collect()
    }

    pub fn exact_companion_classes(
        &self,
        scala: &dyn ScalaSource,
        target: &CodeUnit,
    ) -> Vec<CodeUnit> {
        let target_parent = self.exact_structural_parent(scala, target);
        self.index
            .by_normalized_fqn(&scala_normalized_fq_name(&target.fq_name()))
            .iter()
            .filter(|candidate| {
                candidate.is_class()
                    && *candidate != target
                    && candidate.source() == target.source()
                    && !candidate.short_name().ends_with('$')
                    && self.exact_structural_parent(scala, candidate) == target_parent
            })
            .cloned()
            .collect()
    }

    /// The case class whose synthetic `apply` an explicit `Owner.apply(...)`
    /// selection names, given the receiver's declaration: a companion object, or
    /// the case class itself when the companion is implicit and the index
    /// therefore carries no `Owner$` unit. `None` when the companion declares an
    /// `apply` of its own, because that declaration is then the callee.
    pub fn synthetic_apply_case_class(
        &self,
        scala: &dyn ScalaSource,
        receiver: &CodeUnit,
    ) -> Option<CodeUnit> {
        let class = if receiver.short_name().ends_with('$') {
            let mut companions = self.exact_companion_classes(scala, receiver).into_iter();
            let class = companions.next()?;
            if companions.next().is_some() {
                return None;
            }
            class
        } else {
            receiver.clone()
        };
        if !self.is_case_class(scala, &class) {
            return None;
        }
        let declares_apply = self
            .exact_companion_objects(scala, &class)
            .iter()
            .any(|companion| {
                self.members_for_exact_owner_unit(scala, companion, "apply")
                    .iter()
                    .any(|unit| unit.is_function())
            });
        (!declares_apply).then_some(class)
    }

    /// Whether `owner` declares an extractor entry point of its own -- an
    /// `unapply` or `unapplySeq` a pattern can name through `owner`.
    pub fn declares_extractor_entry_point(
        &self,
        scala: &dyn ScalaSource,
        owner: &CodeUnit,
    ) -> bool {
        ["unapply", "unapplySeq"].into_iter().any(|member| {
            self.members_for_exact_owner_unit(scala, owner, member)
                .iter()
                .any(|unit| unit.is_function())
        })
    }

    /// The extractor entry points `owner` declares.
    ///
    /// An extractor pattern says nothing about the parameter list of the
    /// `unapply` behind it -- `case Foo(a, b)` writes the *result* the
    /// extractor yields -- so ordinary call-shape matching cannot choose among
    /// the entry points one owner declares. When the owner declares overloads,
    /// the scrutinee type selects one, and that type is not modeled here, so
    /// the site names the whole family (#2078).
    pub fn extractor_entry_points(
        &self,
        scala: &dyn ScalaSource,
        owner: &CodeUnit,
    ) -> Vec<CodeUnit> {
        let mut entry_points = Vec::new();
        for member in ["unapply", "unapplySeq"] {
            entry_points.extend(
                self.members_for_exact_owner_unit(scala, owner, member)
                    .into_iter()
                    .filter(|unit| unit.is_function()),
            );
        }
        entry_points
    }

    pub fn class_accepts_extractor_role(&self, scala: &dyn ScalaSource, target: &CodeUnit) -> bool {
        self.is_case_class(scala, target)
            || self
                .exact_companion_objects(scala, target)
                .iter()
                .any(|companion| self.declares_extractor_entry_point(scala, companion))
    }

    fn class_application_matches_with_shape(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        resolver: &NameResolver,
        target: &CodeUnit,
        call_shape: Option<&ScalaCallSiteShape>,
    ) -> bool {
        if self.class_companion_apply_call_matches_with_shape(
            scala, token, resolver, target, call_shape,
        ) {
            return true;
        }
        if self
            .exact_companion_objects(scala, target)
            .iter()
            .any(|companion| {
                self.members_for_exact_owner_unit(scala, companion, "apply")
                    .iter()
                    .any(|unit| {
                        unit.is_function()
                            && call_shape.is_some_and(|shape| {
                                !self
                                    .callable_declarations_for_members_with_shape(
                                        scala,
                                        token,
                                        std::slice::from_ref(unit),
                                        shape,
                                        ScalaCallableSiteRole::Ordinary,
                                    )
                                    .is_empty()
                            })
                    })
            })
        {
            return false;
        }
        self.constructor_target_matches(
            scala,
            token,
            target,
            call_shape,
            ScalaCallableSiteRole::PrimaryConstruction,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn resolve_type_application(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        resolver: &NameResolver,
        class_fqn: Option<&str>,
        object_fqn: Option<&str>,
        name: &str,
        call_shape: Option<&ScalaCallSiteShape>,
        role: TypeApplicationRole,
        reference_file: Option<&ProjectFile>,
    ) -> TypeApplicationResolution {
        let mut type_candidates = class_fqn
            .map(|fqn| {
                self.index
                    .by_fqn(fqn)
                    .into_iter()
                    .filter(|unit| unit.is_class() && !unit.short_name().ends_with('$'))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if let Some(reference_file) = reference_file {
            let same_file = type_candidates
                .iter()
                .filter(|unit| unit.source() == reference_file)
                .cloned()
                .collect::<Vec<_>>();
            if !same_file.is_empty() {
                type_candidates = same_file;
            }
        }
        let type_target = (type_candidates.len() == 1).then(|| type_candidates[0].clone());
        if role == TypeApplicationRole::Extractor {
            let extractor_owners = if !type_candidates.is_empty() {
                type_candidates
                    .iter()
                    .flat_map(|target| self.exact_companion_objects(scala, target))
                    .collect::<Vec<_>>()
            } else {
                let owners = object_fqn
                    .into_iter()
                    .flat_map(|fqn| self.index.by_fqn(fqn))
                    .filter(|unit| unit.is_class())
                    .collect::<Vec<_>>();
                let same_file = reference_file
                    .map(|file| {
                        owners
                            .iter()
                            .filter(|unit| unit.source() == file)
                            .cloned()
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if same_file.is_empty() {
                    owners
                } else {
                    same_file
                }
            };
            let unapply_targets = extractor_owners
                .iter()
                .flat_map(|companion| self.extractor_entry_points(scala, companion))
                .collect::<Vec<_>>();
            let mut callable_targets = match self.physical_callable_targets(scala, unapply_targets)
            {
                PhysicalCallableTargets::Unique(targets) => targets,
                PhysicalCallableTargets::Ambiguous => Vec::new(),
                PhysicalCallableTargets::NoCandidates => {
                    let primary_targets = type_candidates
                        .iter()
                        .flat_map(|target| {
                            let members = self.members_for_exact_owner_unit(scala, target, name);
                            self.callable_declarations_for_members(
                                scala,
                                token,
                                &members,
                                call_shape,
                                ScalaCallableSiteRole::PrimaryConstruction,
                            )
                        })
                        .collect::<Vec<_>>();
                    match self.physical_callable_targets(scala, primary_targets) {
                        PhysicalCallableTargets::Unique(targets) => targets,
                        PhysicalCallableTargets::NoCandidates
                        | PhysicalCallableTargets::Ambiguous => Vec::new(),
                    }
                }
            };
            let mut seen = HashSet::default();
            callable_targets.retain(|target| seen.insert(target.clone()));
            return TypeApplicationResolution {
                type_target: type_target
                    .filter(|target| self.class_accepts_extractor_role(scala, target)),
                callable_targets,
                value_result: None,
            };
        }

        if role == TypeApplicationRole::ExplicitConstructor {
            let callable_targets = type_candidates
                .iter()
                .flat_map(|target| {
                    let members = self.members_for_exact_owner_unit(scala, target, name);
                    self.callable_declarations_for_members(
                        scala,
                        token,
                        &members,
                        call_shape,
                        ScalaCallableSiteRole::ExplicitConstruction,
                    )
                })
                .collect::<Vec<_>>();
            let callable_targets = self
                .physical_callable_targets(scala, callable_targets)
                .into_unique();
            let type_target = type_target.filter(|target| {
                self.is_scala_trait_declaration(scala, target) || {
                    let members = self.members_for_exact_owner_unit(scala, target, name);
                    !self
                        .callable_declarations_for_members(
                            scala,
                            token,
                            &members,
                            call_shape,
                            ScalaCallableSiteRole::ExplicitConstruction,
                        )
                        .is_empty()
                        || self.constructor_target_matches(
                            scala,
                            token,
                            target,
                            call_shape,
                            ScalaCallableSiteRole::ExplicitConstruction,
                        )
                }
            });
            return TypeApplicationResolution {
                value_result: type_target.clone().map(ScalaValueOwner::Exact),
                type_target,
                callable_targets,
            };
        }

        let apply_owners = if !type_candidates.is_empty() {
            type_candidates
                .iter()
                .flat_map(|target| self.exact_companion_objects(scala, target))
                .collect::<Vec<_>>()
        } else {
            let owners = object_fqn
                .into_iter()
                .flat_map(|fqn| self.index.by_fqn(fqn))
                .filter(|unit| unit.is_class())
                .collect::<Vec<_>>();
            let same_file = reference_file
                .map(|file| {
                    owners
                        .iter()
                        .filter(|unit| unit.source() == file)
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if same_file.is_empty() {
                owners
            } else {
                same_file
            }
        };
        if apply_owners.len() > 1 {
            return TypeApplicationResolution {
                type_target: None,
                callable_targets: Vec::new(),
                value_result: None,
            };
        }
        // A case class's `apply` is synthesized in its own companion, so it is an
        // own member of that object and outranks any `apply` the companion merely
        // inherits from a supertype. `object P extends SpanContainerCompanion`
        // next to `case class P(...)` is exactly that shape: the inherited
        // overloads would otherwise consume `P(spans)` and leave the site with no
        // edge at all, while `get_definition` names the constructor.
        let synthetic_companion_apply = type_target.as_ref().is_some_and(|target| {
            self.is_case_class(scala, target)
                && apply_owners.first().is_some_and(|companion| {
                    self.members_for_exact_owner_unit(scala, companion, "apply")
                        .is_empty()
                })
        });
        let apply_resolution = apply_owners
            .first()
            .filter(|_| !synthetic_companion_apply)
            .map(|owner| self.inherited_apply_value_resolution(scala, token, owner, call_shape))
            .unwrap_or(ScalaApplyValueResolution::NoDeclaration);
        let apply_resolution = match apply_resolution {
            ScalaApplyValueResolution::NoDeclaration => {
                if let (Some(type_target), Some(companion)) =
                    (type_target.as_ref(), apply_owners.first())
                    && !self.is_case_class(scala, type_target)
                    && let Some(callable) = self.unresolved_inherited_companion_apply_fallback(
                        scala,
                        token,
                        type_target,
                        companion,
                        call_shape,
                    )
                {
                    return TypeApplicationResolution {
                        type_target: None,
                        callable_targets: vec![callable],
                        value_result: None,
                    };
                }
                None
            }
            ScalaApplyValueResolution::NoApplicableCallable => None,
            ScalaApplyValueResolution::Authoritative(None) => {
                return TypeApplicationResolution {
                    type_target: None,
                    callable_targets: Vec::new(),
                    value_result: None,
                };
            }
            ScalaApplyValueResolution::Authoritative(resolution) => resolution,
        };
        let apply_targets = apply_resolution
            .as_ref()
            .map(|resolution| resolution.callable_targets.clone())
            .unwrap_or_default();
        match self.physical_callable_targets(scala, apply_targets) {
            PhysicalCallableTargets::Unique(mut apply_targets) => {
                if !type_candidates.is_empty() {
                    let mut seen = HashSet::default();
                    apply_targets.retain(|target| seen.insert(target.clone()));
                }
                let value_result = apply_resolution.and_then(|resolution| resolution.value_result);
                return TypeApplicationResolution {
                    type_target: type_target.filter(|target| {
                        value_result.as_ref().is_some_and(|value| match value {
                            ScalaValueOwner::Exact(owner) => owner == target,
                            ScalaValueOwner::Logical(fqn) => {
                                scala_normalized_fq_name(fqn)
                                    == scala_normalized_fq_name(&target.fq_name())
                            }
                        })
                    }),
                    callable_targets: apply_targets,
                    value_result,
                };
            }
            PhysicalCallableTargets::Ambiguous => {
                return TypeApplicationResolution {
                    type_target: None,
                    callable_targets: Vec::new(),
                    value_result: None,
                };
            }
            PhysicalCallableTargets::NoCandidates => {}
        }

        let callable_targets = type_candidates
            .iter()
            .flat_map(|target| {
                let members = self.members_for_exact_owner_unit(scala, target, name);
                self.callable_declarations_for_members(
                    scala,
                    token,
                    &members,
                    call_shape,
                    ScalaCallableSiteRole::PrimaryConstruction,
                )
            })
            .collect::<Vec<_>>();
        let callable_targets = self
            .physical_callable_targets(scala, callable_targets)
            .into_unique();
        TypeApplicationResolution {
            value_result: type_target
                .as_ref()
                .filter(|target| {
                    self.class_application_matches_with_shape(
                        scala, token, resolver, target, call_shape,
                    )
                })
                .cloned()
                .map(ScalaValueOwner::Exact),
            type_target: type_target.filter(|target| {
                self.class_application_matches_with_shape(
                    scala, token, resolver, target, call_shape,
                )
            }),
            callable_targets,
        }
    }

    fn unresolved_inherited_companion_apply_fallback(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        type_target: &CodeUnit,
        companion: &CodeUnit,
        call_shape: Option<&ScalaCallSiteShape>,
    ) -> Option<CodeUnit> {
        let normalized_owner = scala_normalized_fq_name(&type_target.fq_name());
        let normalized_owners = self.index.by_normalized_fqn(&normalized_owner);
        let mut physical_companions = normalized_owners.iter().filter(|candidate| {
            candidate.is_class()
                && *candidate != type_target
                && self.type_accepts_object_roles(scala, candidate)
        });
        let physical_companion = physical_companions.next()?;
        if physical_companion != companion || physical_companions.next().is_some() {
            return None;
        }

        let facts = scala.forward_owner_facts(companion)?;
        if facts.supertype_lookup_paths.is_empty() {
            return None;
        }

        let members = self.members_for_exact_owner_unit(scala, type_target, "apply");
        let mut callables = self.callable_declarations_for_members(
            scala,
            token,
            &members,
            call_shape,
            ScalaCallableSiteRole::Ordinary,
        );
        callables.sort();
        callables.dedup();
        match callables.as_slice() {
            [callable] => Some(callable.clone()),
            _ => None,
        }
    }

    pub fn class_accepts_apply_role(&self, scala: &dyn ScalaSource, target: &CodeUnit) -> bool {
        self.is_case_class(scala, target)
            || self
                .exact_companion_objects(scala, target)
                .iter()
                .any(|companion| {
                    self.members_for_exact_owner_unit(scala, companion, "apply")
                        .iter()
                        .any(|unit| unit.is_function())
                })
    }

    fn class_companion_apply_call_matches_with_shape(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        resolver: &NameResolver,
        target: &CodeUnit,
        call_shape: Option<&ScalaCallSiteShape>,
    ) -> bool {
        if self.is_case_class(scala, target)
            && self.constructor_target_matches(
                scala,
                token,
                target,
                call_shape,
                ScalaCallableSiteRole::PrimaryConstruction,
            )
        {
            return true;
        }
        self.exact_companion_objects(scala, target)
            .iter()
            .any(|companion| {
                call_shape
                    .and_then(|shape| {
                        let members = self.members_for_exact_owner_unit(scala, companion, "apply");
                        self.member_return_type_for_members_with_shape(
                            scala,
                            token,
                            resolver,
                            &members,
                            Some(shape),
                        )
                    })
                    .is_some_and(|return_type| {
                        scala_normalized_fq_name(&return_type)
                            == scala_normalized_fq_name(&target.fq_name())
                    })
            })
    }

    pub fn class_companion_apply_method_value_matches(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        target: &CodeUnit,
        contextual_arities: Option<&[usize]>,
    ) -> bool {
        let mut alternatives = Vec::new();
        if self.is_case_class(scala, target) {
            alternatives.extend(
                self.callable_alternatives_for(scala, token, target)
                    .iter()
                    .filter(|alternative| alternative.role == ScalaCallableRole::PrimaryConstructor)
                    .cloned()
                    .map(|mut alternative| {
                        alternative.role = ScalaCallableRole::Ordinary;
                        alternative
                    }),
            );
        }
        let normalized_target = scala_normalized_fq_name(&target.fq_name());
        for companion in self.exact_companion_objects(scala, target) {
            for apply in self
                .members_for_exact_owner_unit(scala, &companion, "apply")
                .iter()
                .filter(|unit| unit.is_function())
            {
                alternatives.extend(
                    self.callable_alternatives_for(scala, token, apply)
                        .iter()
                        .filter(|alternative| {
                            alternative.role == ScalaCallableRole::Ordinary
                                && alternative
                                    .return_type
                                    .as_deref()
                                    .is_some_and(|return_type| {
                                        scala_normalized_fq_name(return_type) == normalized_target
                                    })
                        })
                        .cloned(),
                );
            }
        }
        let matches = alternatives
            .iter()
            .filter(|alternative| {
                alternative.role == ScalaCallableRole::Ordinary
                    && contextual_arities.is_none_or(|arities| {
                        ordinary_callable_shape_matches(alternative, Some(arities), false)
                    })
            })
            .count();
        matches == 1
    }

    fn unique_companion_apply_method_value_target(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        resolver: &NameResolver,
        name: &str,
        contextual_arities: Option<&[usize]>,
    ) -> Option<CodeUnit> {
        let fqn = resolver.resolve(name)?;
        let mut targets = self
            .index
            .by_fqn(&fqn)
            .into_iter()
            .filter(|unit| unit.is_class() && !unit.short_name().ends_with('$'));
        let target = targets.next()?;
        if targets.next().is_some()
            || !self.class_companion_apply_method_value_matches(
                scala,
                token,
                &target,
                contextual_arities,
            )
        {
            return None;
        }
        Some(target)
    }

    pub fn is_case_class(&self, scala: &dyn ScalaSource, target: &CodeUnit) -> bool {
        let source_facts = self.source_facts_for_file(scala, target.source());
        self.declaration_ranges_for(scala, target)
            .iter()
            .any(|range| {
                source_facts
                    .case_class_ranges
                    .contains(&(range.start_byte, range.end_byte))
            })
    }

    pub fn is_enum(&self, scala: &dyn ScalaSource, target: &CodeUnit) -> bool {
        let source_facts = self.source_facts_for_file(scala, target.source());
        self.declaration_ranges_for(scala, target)
            .iter()
            .any(|range| {
                source_facts
                    .enum_ranges
                    .contains(&(range.start_byte, range.end_byte))
            })
    }

    fn declaration_ranges_for(&self, scala: &dyn ScalaSource, target: &CodeUnit) -> Vec<Range> {
        match &self.bulk_file_states {
            Some(states) => states
                .get(target.source())
                .and_then(|state| state.ranges.get(target))
                .cloned()
                .unwrap_or_default(),
            None => scala.ranges(target),
        }
    }

    fn signature_metadata_for(
        &self,
        scala: &dyn ScalaSource,
        target: &CodeUnit,
    ) -> Vec<SignatureMetadata> {
        match &self.bulk_file_states {
            Some(states) => states
                .get(target.source())
                .and_then(|state| state.signature_metadata.get(target))
                .cloned()
                .unwrap_or_default(),
            None => scala.signature_metadata(target),
        }
    }

    fn source_facts_for_file(
        &self,
        scala: &dyn ScalaSource,
        file: &ProjectFile,
    ) -> CachedScalaSourceFacts {
        let cell = self
            .source_facts_by_file
            .lock()
            .expect("Scala source-facts cache poisoned")
            .entry(file.clone())
            .or_insert_with(|| Arc::new(OnceLock::new()))
            .clone();
        cell.get_or_init(|| {
            Arc::new(
                self.source_for_file(scala, file)
                    .and_then(|source| scala_source_facts(&source))
                    .unwrap_or_default(),
            )
        })
        .clone()
    }

    pub fn source_for_file(&self, scala: &dyn ScalaSource, file: &ProjectFile) -> Option<String> {
        match &self.bulk_file_states {
            Some(states) => states
                .get(file)
                .map(|state| state.source.as_str())
                .filter(|source| !source.is_empty())
                .map(str::to_owned)
                .or_else(|| scala.indexed_source(file)),
            None => scala.indexed_source(file),
        }
    }

    fn direct_extension_method(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        normalized_fqn: &str,
    ) -> Vec<ExtensionMethod> {
        self.index
            .by_normalized_fqn(normalized_fqn)
            .iter()
            .filter(|unit| unit.is_function() || unit.is_field())
            .filter_map(|unit| self.extension_method_for_unit(scala, token, unit))
            .collect()
    }

    fn extension_methods_for_owner_member(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        normalized_owner_fqn: &str,
        member: &str,
    ) -> ExtensionMethodEntries {
        let key = (normalized_owner_fqn.to_string(), member.to_string());
        if let Some(methods) = self
            .extension_methods_by_owner_member
            .lock()
            .expect("extension method cache poisoned")
            .get(&key)
            .cloned()
        {
            return methods;
        }

        let mut methods = self
            .index
            .members_for_owner_name(normalized_owner_fqn, normalized_owner_fqn, member)
            .into_iter()
            .filter(|unit| unit.is_function() || unit.is_field())
            .filter_map(|unit| self.extension_method_for_unit(scala, token, &unit))
            .collect::<Vec<_>>();
        methods.sort_by(|left, right| left.declaration.cmp(&right.declaration));
        methods.dedup_by(|left, right| left.declaration == right.declaration);
        let methods = Arc::new(methods);
        self.extension_methods_by_owner_member
            .lock()
            .expect("extension method cache poisoned")
            .insert(key, methods.clone());
        methods
    }

    fn extension_method_for_unit(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        unit: &CodeUnit,
    ) -> Option<ExtensionMethod> {
        let alternatives = self.callable_alternatives_for(scala, token, unit);
        if !alternatives
            .iter()
            .any(|alternative| alternative.extension_receiver_type.is_some())
        {
            return None;
        }
        let _ = owner_fqn(unit)?;
        Some(ExtensionMethod {
            declaration: unit.clone(),
            alternatives,
        })
    }

    fn override_targets_for_method(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        owner_fqn: &str,
        method_fqn: &str,
        method_name: &str,
        method_arity: Option<usize>,
    ) -> OverrideTargetEntries {
        let key = method_key(method_fqn, method_arity);
        if let Some(targets) = self
            .override_targets_by_method
            .lock()
            .expect("override target cache poisoned")
            .get(&key)
            .cloned()
        {
            return targets;
        }

        let mut level = self.direct_ancestors_for_owner(scala, owner_fqn);
        let mut seen = HashSet::default();
        let mut targets = Vec::new();
        while !level.is_empty() {
            let mut next = Vec::new();
            for ancestor in level {
                if !seen.insert(ancestor.clone()) {
                    continue;
                }
                next.extend(self.direct_ancestors_for_declaration(scala, &ancestor));
                let ancestor_owner = ancestor.fq_name();
                let normalized_ancestor_owner = scala_normalized_fq_name(&ancestor_owner);
                targets.extend(
                    self.index
                        .members_for_owner_name(
                            &ancestor_owner,
                            &normalized_ancestor_owner,
                            method_name,
                        )
                        .iter()
                        .filter(|ancestor_method| {
                            ancestor_method.is_function()
                                && method_arities_compatible(
                                    method_arity,
                                    self.callable_facts(scala, token, ancestor_method)
                                        .and_then(|facts| facts.arity),
                                )
                        })
                        .map(|ancestor_method| (*ancestor_method).clone()),
                );
            }
            if !targets.is_empty() {
                break;
            }
            level = next;
        }
        targets.sort();
        targets.dedup();

        let targets = Arc::new(targets);
        self.override_targets_by_method
            .lock()
            .expect("override target cache poisoned")
            .insert(key, targets.clone());
        targets
    }
}

#[derive(Clone)]
pub struct CallableAlternative {
    pub role: ScalaCallableRole,
    pub shape: Vec<ScalaCallableParameterList>,
    pub result: ScalaDeclaredResult,
    pub parameter_defaults: Vec<Vec<bool>>,
    pub parameter_types: Vec<Vec<Option<ScalaParameterTypeIdentity>>>,
    pub parameter_function_shapes: Vec<Vec<Option<ScalaFunctionParameterShape>>>,
    pub extension_receiver_type: Option<String>,
    pub return_type: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OverrideFamilyRelation {
    Exact,
    Different,
    Unknown,
}

fn override_family_relation(
    declared: &CallableAlternative,
    ancestor: &CallableAlternative,
) -> OverrideFamilyRelation {
    if declared.role != ScalaCallableRole::Ordinary
        || ancestor.role != ScalaCallableRole::Ordinary
        || declared.shape.len() != ancestor.shape.len()
    {
        return OverrideFamilyRelation::Different;
    }
    for (declared_list, ancestor_list) in declared.shape.iter().zip(&ancestor.shape) {
        if declared_list.kind != ancestor_list.kind
            || declared_list.arity.total() != ancestor_list.arity.total()
            || callable_arity_is_repeated(declared_list.arity)
                != callable_arity_is_repeated(ancestor_list.arity)
        {
            return OverrideFamilyRelation::Different;
        }
    }
    if declared.parameter_types.len() != declared.shape.len()
        || ancestor.parameter_types.len() != ancestor.shape.len()
    {
        return OverrideFamilyRelation::Unknown;
    }
    for ((declared_types, ancestor_types), declared_shape) in declared
        .parameter_types
        .iter()
        .zip(&ancestor.parameter_types)
        .zip(&declared.shape)
    {
        if declared_types.len() != declared_shape.arity.total()
            || ancestor_types.len() != declared_shape.arity.total()
        {
            return OverrideFamilyRelation::Unknown;
        }
        for (declared_type, ancestor_type) in declared_types.iter().zip(ancestor_types) {
            match (declared_type, ancestor_type) {
                (
                    Some(
                        ScalaParameterTypeIdentity::LogicalCandidates(_)
                        | ScalaParameterTypeIdentity::Unresolved(_),
                    ),
                    _,
                )
                | (
                    _,
                    Some(
                        ScalaParameterTypeIdentity::LogicalCandidates(_)
                        | ScalaParameterTypeIdentity::Unresolved(_),
                    ),
                ) => {
                    return OverrideFamilyRelation::Unknown;
                }
                (Some(declared_type), Some(ancestor_type)) if declared_type == ancestor_type => {}
                (Some(_), Some(_)) => return OverrideFamilyRelation::Different,
                _ => return OverrideFamilyRelation::Unknown,
            }
        }
    }
    OverrideFamilyRelation::Exact
}

fn callable_arity_is_repeated(arity: CallableArity) -> bool {
    arity.accepts(arity.total().saturating_add(1))
}

fn apply_parameter_defaults_to_shape(alternative: &mut CallableAlternative) {
    for (list, defaults) in alternative
        .shape
        .iter_mut()
        .zip(&alternative.parameter_defaults)
    {
        let total = list.arity.total();
        if defaults.len() != total {
            continue;
        }
        let repeated = callable_arity_is_repeated(list.arity);
        let required = total
            .saturating_sub(defaults.iter().filter(|is_default| **is_default).count())
            .saturating_sub(usize::from(repeated));
        list.arity = CallableArity::new(required, total, repeated);
    }
}

pub fn callable_alternative_is_candidate(
    alternative: &CallableAlternative,
    actual: &ScalaCallSiteShape,
    site_role: ScalaCallableSiteRole,
) -> bool {
    scala_callable_alternative_is_candidate(
        alternative.role,
        &alternative.shape,
        alternative.result,
        actual,
        site_role,
    ) && method_value_parameter_types_match(alternative, actual)
}

pub fn callable_alternative_matches(
    alternative: &CallableAlternative,
    actual: Option<&ScalaCallSiteShape>,
    site_role: ScalaCallableSiteRole,
    unique_callable: bool,
) -> bool {
    scala_callable_alternative_matches(
        alternative.role,
        &alternative.shape,
        alternative.result,
        actual,
        site_role,
        unique_callable,
    ) && actual.is_none_or(|actual| method_value_parameter_types_match(alternative, actual))
}

fn method_value_parameter_types_match(
    alternative: &CallableAlternative,
    actual: &ScalaCallSiteShape,
) -> bool {
    let Some(list_index) = next_explicit_parameter_list_index(&alternative.shape, actual) else {
        // Once all explicit lists have been consumed, the surrounding
        // function expectation describes the callable's return value rather
        // than another curried parameter list. It therefore cannot reject the
        // completed call even when that return-function parameter is generic
        // or otherwise lacks an exact physical identity.
        return true;
    };
    let Some(declared) = alternative.parameter_types.get(list_index) else {
        return false;
    };
    if declared
        .iter()
        .any(|identity| matches!(identity, Some(ScalaParameterTypeIdentity::Unresolved(_))))
    {
        return false;
    }
    if actual
        .method_value_parameter_types
        .as_ref()
        .is_some_and(|types| {
            types
                .iter()
                .any(|identity| matches!(identity, ScalaParameterTypeIdentity::Unresolved(_)))
        })
    {
        return false;
    }
    if !actual.method_value_parameter_types_authoritative {
        return true;
    }
    let Some(expected) = actual.method_value_parameter_types.as_ref() else {
        return false;
    };
    declared.len() == expected.len()
        && declared.iter().zip(expected).all(|(declared, expected)| {
            declared
                .as_ref()
                .is_some_and(|declared| parameter_type_identities_match(declared, expected))
        })
}

fn parameter_type_identities_match(
    declared: &ScalaParameterTypeIdentity,
    expected: &ScalaParameterTypeIdentity,
) -> bool {
    match (declared, expected) {
        (
            ScalaParameterTypeIdentity::LogicalCandidates(candidates),
            ScalaParameterTypeIdentity::Logical(expected),
        ) => candidates.contains(expected),
        (
            ScalaParameterTypeIdentity::Logical(declared),
            ScalaParameterTypeIdentity::LogicalCandidates(candidates),
        ) => candidates.contains(declared),
        (
            ScalaParameterTypeIdentity::LogicalCandidates(_),
            ScalaParameterTypeIdentity::LogicalCandidates(_),
        ) => false,
        _ => declared == expected,
    }
}

/// True when the call site's known literal argument types prove this
/// alternative cannot be the callee: some position pairs a literal whose
/// builtin type contradicts the declared builtin parameter type outside the
/// numeric-widening family. Everything uncertain (non-literal arguments,
/// named arguments, defaults, arity mismatch, non-builtin parameter types)
/// answers `false` - a wrong absence is worse than a union (#1327).
pub fn callable_alternative_contradicts_literal_arguments(
    alternative: &CallableAlternative,
    call_shape: &ScalaCallSiteShape,
) -> bool {
    let Some(literals) = call_shape.leading_literal_argument_types.as_ref() else {
        return false;
    };
    let Some(index) = alternative
        .shape
        .iter()
        .position(|list| list.kind == super::syntax::ScalaParameterListKind::Explicit)
    else {
        return false;
    };
    let Some(parameter_types) = alternative.parameter_types.get(index) else {
        return false;
    };
    if parameter_types.len() != literals.len()
        || alternative
            .parameter_defaults
            .get(index)
            .is_some_and(|defaults| defaults.iter().any(|default| *default))
    {
        return false;
    }
    literals
        .iter()
        .zip(parameter_types)
        .any(|(literal, expected)| match (literal, expected) {
            (Some(literal), Some(ScalaParameterTypeIdentity::Builtin(expected))) => {
                literal != expected && !super::resolver::scala_numeric_builtins(literal, expected)
            }
            _ => false,
        })
}

fn next_explicit_parameter_list_index(
    declared: &[ScalaCallableParameterList],
    actual: &ScalaCallSiteShape,
) -> Option<usize> {
    let mut declared_index = 0usize;
    for actual_list in &actual.lists {
        if matches!(
            actual_list.kind,
            super::syntax::ScalaCallArgumentListKind::Ordinary
                | super::syntax::ScalaCallArgumentListKind::Block
        ) {
            while declared
                .get(declared_index)
                .is_some_and(|list| list.kind == super::syntax::ScalaParameterListKind::Contextual)
            {
                declared_index += 1;
            }
        }
        declared.get(declared_index)?;
        declared_index += 1;
    }
    let mut remaining = declared
        .iter()
        .enumerate()
        .skip(declared_index)
        .filter(|(_, list)| list.kind == super::syntax::ScalaParameterListKind::Explicit);
    let (index, _) = remaining.next()?;
    remaining.next().is_none().then_some(index)
}

#[derive(Clone)]
pub struct ExtensionMethod {
    pub declaration: CodeUnit,
    alternatives: CachedCallableAlternatives,
}

/// Per-file map from a source-visible type/object name to the analyzer's fqn,
/// mirroring the forward scanner's visibility rules.
pub struct NameResolver {
    names: VisibleNameBindings,
    object_names: VisibleNameBindings,
    package_names: VisibleNameBindings,
    logical_type_names: VisibleNameBindings,
    logical_wildcard_type_owners: HashSet<String>,
    ambiguous_import_priorities: HashMap<String, u8>,
    package_prefixes: Vec<String>,
    member_names: VisibleNameBindings,
    direct_extension_methods: HashMap<String, Vec<ExtensionMethod>>,
    wildcard_extension_owners: Vec<String>,
}

#[derive(Default)]
struct VisibleNameBindings {
    entries: HashMap<String, VisibleNameBinding>,
}

struct VisibleNameBinding {
    /// Namespace rank, compared before `priority`. See `NAMESPACE_TIER` and
    /// `OBJECT_TYPE_NAMESPACE_TIER`.
    tier: u8,
    priority: u8,
    candidates: HashSet<String>,
    declarations: HashSet<CodeUnit>,
}

/// The rank of a declaration that binds its name in the namespace it is added
/// to. Every binding outside the type namespace carries this rank, so there
/// lexical `priority` alone decides.
const NAMESPACE_TIER: u8 = 1;

/// The rank of a declared `object` inside the type namespace. Scala keeps terms
/// and types in separate namespaces: `object O` binds `O` in the term namespace
/// and contributes only `O.type` to the type namespace, so a bare type
/// reference never means the object. Ranking it below every class, trait, and
/// type alias keeps a nearer object from displacing a type of the same name --
/// scalaz writes `import Free._` beside a sibling `object Trampoline`, and
/// `Trampoline[A]` there is `Free.Trampoline`.
const OBJECT_TYPE_NAMESPACE_TIER: u8 = 0;

impl VisibleNameBindings {
    fn add_declaration(&mut self, name: String, declaration: &CodeUnit, priority: u8) {
        self.add_candidate(
            name,
            declaration.fq_name(),
            Some(declaration.clone()),
            NAMESPACE_TIER,
            priority,
        );
    }

    /// Add a declaration to the type namespace, where a declared `object` ranks
    /// below every class, trait, and type alias that binds the same name.
    fn add_type_declaration(
        &mut self,
        name: String,
        declaration: &CodeUnit,
        types: &ProjectTypes,
        priority: u8,
    ) {
        self.add_candidate(
            name,
            declaration.fq_name(),
            Some(declaration.clone()),
            types.type_namespace_tier(declaration),
            priority,
        );
    }

    fn add_candidate(
        &mut self,
        name: String,
        fqn: String,
        declaration: Option<CodeUnit>,
        tier: u8,
        priority: u8,
    ) {
        match self.entries.entry(name) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(VisibleNameBinding {
                    tier,
                    priority,
                    candidates: HashSet::from_iter([fqn]),
                    declarations: declaration.into_iter().collect(),
                });
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let binding = entry.get_mut();
                match (tier, priority).cmp(&(binding.tier, binding.priority)) {
                    std::cmp::Ordering::Greater => {
                        binding.tier = tier;
                        binding.priority = priority;
                        binding.candidates.clear();
                        binding.candidates.insert(fqn);
                        binding.declarations.clear();
                        binding.declarations.extend(declaration);
                    }
                    std::cmp::Ordering::Equal => {
                        binding.candidates.insert(fqn);
                        binding.declarations.extend(declaration);
                    }
                    std::cmp::Ordering::Less => {}
                }
            }
        }
    }

    fn resolve(&self, name: &str) -> Option<String> {
        let binding = self.entries.get(name)?;
        (binding.candidates.len() == 1 && single_replica_family(binding.declarations.iter()))
            .then(|| binding.candidates.iter().next().cloned())?
    }

    fn resolve_logical(&self, name: &str) -> Option<String> {
        let binding = self.entries.get(name)?;
        (binding.candidates.len() == 1).then(|| binding.candidates.iter().next().cloned())?
    }

    fn resolve_exact(&self, name: &str) -> Option<CodeUnit> {
        let binding = self.entries.get(name)?;
        let declarations = binding.declarations.iter().collect::<Vec<_>>();
        let [declaration] = declarations.as_slice() else {
            return None;
        };
        (binding.candidates.len() == 1).then(|| (*declaration).clone())
    }

    /// Every physical declaration a bare name binds to when they are all one
    /// logical Scala symbol (#2021): one candidate fully qualified name, a
    /// non-empty declaration set, and a declaration set that is a single
    /// replica family. This is the plural sibling of [`Self::resolve_exact`],
    /// which insists on exactly one declaration and is therefore the funnel
    /// that drops cross-built replicas.
    ///
    /// It is deliberately NOT the same as [`Self::resolve_exact_candidates`],
    /// which carries no coherence gate at all because its caller layers an
    /// import-collision check on top instead.
    fn resolve_exact_units(&self, name: &str) -> Vec<CodeUnit> {
        let Some(binding) = self.entries.get(name) else {
            return Vec::new();
        };
        if binding.candidates.len() != 1
            || binding.declarations.is_empty()
            || !single_replica_family(binding.declarations.iter())
        {
            return Vec::new();
        }
        sorted_unique_units(binding.declarations.iter().cloned().collect())
    }

    fn resolve_exact_candidates(&self, name: &str) -> Vec<CodeUnit> {
        let Some(binding) = self.entries.get(name) else {
            return Vec::new();
        };
        if binding.candidates.len() != 1 || binding.declarations.is_empty() {
            return Vec::new();
        }
        sorted_unique_units(binding.declarations.iter().cloned().collect())
    }

    fn resolve_declaration(&self, name: &str) -> ScalaQualifiedTypeRootResolution {
        let Some(binding) = self.entries.get(name) else {
            return ScalaQualifiedTypeRootResolution::NoMatch;
        };
        if binding.candidates.len() == 1 && !binding.declarations.is_empty() {
            ScalaQualifiedTypeRootResolution::Resolved(
                ScalaQualifiedTypeRootBinding::StableObjects(sorted_unique_units(
                    binding.declarations.iter().cloned().collect(),
                )),
            )
        } else {
            ScalaQualifiedTypeRootResolution::Ambiguous
        }
    }

    fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    fn is_ambiguous(&self, name: &str) -> bool {
        self.entries
            .get(name)
            .is_some_and(|binding| binding.candidates.len() != 1 || binding.declarations.len() > 1)
    }

    fn priority(&self, name: &str) -> Option<u8> {
        self.entries.get(name).map(|binding| binding.priority)
    }
}

fn add_wildcard_member_bindings(
    member_names: &mut VisibleNameBindings,
    declarations: impl IntoIterator<Item = CodeUnit>,
) {
    for declaration in declarations {
        if declaration.is_function() || declaration.is_field() {
            let visible_name = scala_short_name_terminal_segment(declaration.short_name());
            member_names.add_declaration(visible_name, &declaration, 128);
        }
    }
}

fn add_hierarchy_package_type_bindings<F>(
    names: &mut VisibleNameBindings,
    types: &ProjectTypes,
    package: &str,
    simple: &str,
    priority: F,
) where
    F: Fn(&CodeUnit) -> u8,
{
    let package_level = types
        .index
        .types_in_package(package, simple)
        .into_iter()
        .filter(|unit| unit.is_class() && is_package_level_type(unit))
        .collect::<Vec<_>>();
    let ordinary = package_level
        .iter()
        .filter(|unit| !unit.short_name().ends_with('$'))
        .cloned()
        .collect::<Vec<_>>();
    let selected = if ordinary.is_empty() {
        package_level
    } else {
        ordinary
    };
    for decl in selected {
        names.add_type_declaration(simple.to_string(), &decl, types, priority(&decl));
    }
}

fn add_hierarchy_package_object_bindings<F>(
    object_names: &mut VisibleNameBindings,
    types: &ProjectTypes,
    package: &str,
    simple: &str,
    priority: F,
) where
    F: Fn(&CodeUnit) -> u8,
{
    for decl in types
        .index
        .types_in_package(package, simple)
        .into_iter()
        .filter(|unit| {
            unit.is_class() && is_package_level_type(unit) && unit.short_name().ends_with('$')
        })
    {
        object_names.add_declaration(simple.to_string(), &decl, priority(&decl));
    }
}

fn scala_default_namespace_is_source_backed(name: &str) -> bool {
    !matches!(
        name,
        // These are compiler-provided lattice types. A source declaration with
        // the same spelling (notably in negative compiler tests) must not turn
        // an intrinsic reference into a physical inverse edge.
        "Any" | "AnyRef" | "Nothing" | "Null" | "Singleton" | "Matchable"
    )
}

impl NameResolver {
    pub fn resolve_unit(&self, name: &str) -> Option<CodeUnit> {
        self.names.resolve_exact(name)
    }

    /// Every physical declaration this name binds to when they are one logical
    /// symbol cross-built across source sets (#2021). Call sites whose
    /// contract is "the reference names this symbol" use this and record one
    /// hit per member; call sites whose contract genuinely needs a single
    /// physical declaration keep [`Self::resolve_unit`].
    pub fn resolve_units(&self, name: &str) -> Vec<CodeUnit> {
        self.names.resolve_exact_units(name)
    }

    pub fn resolve_object_unit(&self, name: &str) -> Option<CodeUnit> {
        self.object_names.resolve_exact(name)
    }

    pub fn resolve_member_unit(&self, name: &str) -> Option<CodeUnit> {
        self.member_names.resolve_exact(name)
    }

    fn resolve_explicit_member_unit(&self, name: &str) -> Option<CodeUnit> {
        (self.member_names.priority(name) == Some(192))
            .then(|| self.member_names.resolve_exact(name))
            .flatten()
    }

    fn resolve_member_units(&self, name: &str) -> Vec<CodeUnit> {
        if self.import_collision_blocks(name, None) {
            return Vec::new();
        }
        self.member_names.resolve_exact_candidates(name)
    }

    pub fn for_file_with_facts(
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        source_file: Option<&ProjectFile>,
        package: Option<&str>,
        imports: &[ImportInfo],
        types: &ProjectTypes,
    ) -> Self {
        let package_prefixes = package.into_iter().map(str::to_string).collect::<Vec<_>>();
        Self::for_file_with_package_context(
            scala,
            token,
            source_file,
            &package_prefixes,
            imports,
            types,
        )
    }

    pub fn for_file_with_package_context(
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        source_file: Option<&ProjectFile>,
        package_prefixes: &[String],
        imports: &[ImportInfo],
        types: &ProjectTypes,
    ) -> Self {
        Self::for_file_with_package_context_and_owner_scopes(
            scala,
            token,
            source_file,
            package_prefixes,
            imports,
            types,
            &HashMap::default(),
        )
    }

    fn for_file_with_package_context_and_owner_scopes(
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        source_file: Option<&ProjectFile>,
        package_prefixes: &[String],
        imports: &[ImportInfo],
        types: &ProjectTypes,
        import_owner_scopes: &HashMap<usize, Vec<String>>,
    ) -> Self {
        Self::for_file_with_facts_impl(
            scala,
            token,
            source_file,
            package_prefixes,
            imports,
            types,
            true,
            import_owner_scopes,
        )
    }

    fn for_type_hierarchy_file(
        source_file: Option<&ProjectFile>,
        package: Option<&str>,
        imports: &[ImportInfo],
        types: &ProjectTypes,
        required_names: &HashSet<String>,
    ) -> Self {
        let mut names = VisibleNameBindings::default();
        let mut object_names = VisibleNameBindings::default();
        let mut package_names = VisibleNameBindings::default();
        let mut ambiguous_import_priorities = HashMap::default();
        let file_package = package.unwrap_or_default();
        let package_prefixes = package.into_iter().map(str::to_string).collect::<Vec<_>>();
        for required in required_names {
            if scala_default_namespace_is_source_backed(required) {
                add_hierarchy_package_type_bindings(&mut names, types, "scala", required, |_| 0);
                add_hierarchy_package_object_bindings(
                    &mut object_names,
                    types,
                    "scala",
                    required,
                    |_| 0,
                );
            }
            add_hierarchy_package_type_bindings(
                &mut names,
                types,
                file_package,
                required,
                |decl| {
                    if source_file == Some(decl.source()) {
                        4
                    } else {
                        1
                    }
                },
            );
            add_hierarchy_package_object_bindings(
                &mut object_names,
                types,
                file_package,
                required,
                |decl| {
                    if source_file == Some(decl.source()) {
                        4
                    } else {
                        1
                    }
                },
            );
        }

        // `for_type_hierarchy_file` never sees a live `ScalaAnalyzer` (it
        // resolves purely from precomputed `ProjectTypes`/imports), so it
        // cannot walk the enclosing-owner chain the way the other resolver
        // construction paths below do; pass an empty chain and keep today's
        // package-only wildcard qualification here.
        let wildcard_environment = resolve_scala_wildcard_import_environment(
            imports,
            &package_prefixes,
            |_declaration_start_byte| Vec::new(),
            |candidate| {
                let normalized = scala_normalized_fq_name(candidate);
                let object_declarations = types.index.by_normalized_fqn(&normalized);
                let mut objects = object_declarations
                    .iter()
                    .filter(|unit| unit.is_class() && unit.short_name().ends_with('$'));
                let stable_singleton = objects.next().is_some() && objects.next().is_none();
                ScalaWildcardOwnerFacts {
                    package: types.index.package_container_exists(candidate),
                    stable_singleton,
                }
            },
        );
        if !wildcard_environment.ambiguous {
            for owner in &wildcard_environment.owners {
                if owner.is_singleton() {
                    let children = types.index.fqn_direct_children(&owner.declaration_fqn());
                    for required in required_names {
                        let ordinary = children
                            .iter()
                            .filter(|unit| {
                                unit.is_class()
                                    && !unit.short_name().ends_with('$')
                                    && scala_simple_type_name(unit) == *required
                            })
                            .collect::<Vec<_>>();
                        for declaration in ordinary {
                            names.add_type_declaration(required.clone(), declaration, types, 2);
                        }
                        for declaration in children.iter().filter(|unit| {
                            unit.is_class()
                                && unit.short_name().ends_with('$')
                                && scala_simple_type_name(unit) == *required
                        }) {
                            object_names.add_declaration(required.clone(), declaration, 2);
                            if !names.contains(required) {
                                names.add_type_declaration(required.clone(), declaration, types, 2);
                            }
                        }
                    }
                } else {
                    for required in required_names {
                        add_hierarchy_package_type_bindings(
                            &mut names,
                            types,
                            &owner.fqn,
                            required,
                            |_| 2,
                        );
                        add_hierarchy_package_object_bindings(
                            &mut object_names,
                            types,
                            &owner.fqn,
                            required,
                            |_| 2,
                        );
                    }
                }
            }
        }

        for import in imports {
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            if import.is_wildcard {
                continue;
            }
            // `ImportInfo::local_name` is the shared `alias ?? identifier ??
            // tail-of-structured-path` desugar; scala's `identifier` is already
            // alias-resolved at construction, so this agrees with the old
            // `identifier ?? terminal-of(path)` fallback exactly.
            if !import
                .local_name()
                .is_some_and(|name| required_names.contains(name))
            {
                continue;
            }
            let local_name = import.local_name().unwrap_or_default();
            let Some(tier) = types.explicit_import_tier(&path, &package_prefixes) else {
                continue;
            };
            if tier.declaration && tier.package {
                ambiguous_import_priorities.insert(local_name.to_string(), 3);
            }
            if tier.declaration {
                let (type_declarations, object_declarations) =
                    types.explicit_import_type_declarations(&tier.candidate);
                for declaration in &type_declarations {
                    names.add_type_declaration(local_name.to_string(), declaration, types, 3);
                }
                for declaration in &object_declarations {
                    object_names.add_declaration(local_name.to_string(), declaration, 3);
                }
            }
            if tier.package {
                package_names.add_candidate(
                    local_name.to_string(),
                    scala_normalized_fq_name(&tier.candidate),
                    None,
                    NAMESPACE_TIER,
                    3,
                );
            }
        }
        Self {
            names,
            object_names,
            package_names,
            logical_type_names: VisibleNameBindings::default(),
            logical_wildcard_type_owners: HashSet::default(),
            ambiguous_import_priorities,
            package_prefixes,
            member_names: VisibleNameBindings::default(),
            direct_extension_methods: HashMap::default(),
            wildcard_extension_owners: Vec::new(),
        }
    }

    pub fn for_file_types(
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        target: &CodeUnit,
        types: &ProjectTypes,
    ) -> Self {
        let file = target.source();
        match &types.bulk_file_states {
            Some(states) => match states.get(file) {
                Some(state) => {
                    let reference_byte = state
                        .ranges
                        .get(target)
                        .into_iter()
                        .flatten()
                        .map(|range| range.start_byte)
                        .min();
                    let imports = visible_imports_at_byte(&state.imports, reference_byte);
                    Self::for_file_with_facts_impl(
                        scala,
                        token,
                        Some(file),
                        &[target.package_name().to_string()],
                        &imports,
                        types,
                        false,
                        &HashMap::default(),
                    )
                }
                None => Self::for_file_with_facts_impl(
                    scala,
                    token,
                    Some(file),
                    &[target.package_name().to_string()],
                    &[],
                    types,
                    false,
                    &HashMap::default(),
                ),
            },
            None => {
                let imports = scala.import_info_of(token, file);
                let reference_byte = scala
                    .ranges(target)
                    .into_iter()
                    .map(|range| range.start_byte)
                    .min();
                let imports = visible_imports_at_byte(&imports, reference_byte);
                Self::for_file_with_facts_impl(
                    scala,
                    token,
                    Some(file),
                    &[target.package_name().to_string()],
                    &imports,
                    types,
                    false,
                    &HashMap::default(),
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn for_file_with_facts_impl(
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        source_file: Option<&ProjectFile>,
        package_prefixes: &[String],
        imports: &[ImportInfo],
        types: &ProjectTypes,
        include_members: bool,
        import_owner_scopes: &HashMap<usize, Vec<String>>,
    ) -> Self {
        let mut names = VisibleNameBindings::default();
        let mut object_names = VisibleNameBindings::default();
        let mut package_names = VisibleNameBindings::default();
        let mut logical_type_names = VisibleNameBindings::default();
        let mut logical_wildcard_type_owners: HashSet<String> = HashSet::default();
        let mut ambiguous_import_priorities = HashMap::default();
        let mut member_names = VisibleNameBindings::default();
        let mut direct_extension_methods: HashMap<String, Vec<ExtensionMethod>> =
            HashMap::default();
        let mut wildcard_extension_owners = Vec::new();

        let fallback_default_package = String::new();
        let active_package_prefixes = if package_prefixes.is_empty() {
            std::slice::from_ref(&fallback_default_package)
        } else {
            package_prefixes
        };
        for import in imports {
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            let normalized = scala_normalized_fq_name(&path);
            if import.is_wildcard {
                // Source-backed wildcard owners are interpreted by the
                // physical namespace resolver below. Do not also invent
                // logical external members that the owner does not declare
                // (for example `import Api.*` must not turn `String` into
                // `Api.String`).
                let has_physical_owner =
                    scala_import_path_candidates(&path, active_package_prefixes)
                        .into_iter()
                        .any(|candidate| {
                            types.index.package_container_exists(&candidate)
                                || types
                                    .object_by_normalized_fqn(
                                        scala,
                                        &scala_normalized_fq_name(&candidate),
                                    )
                                    .is_some()
                        });
                if !has_physical_owner {
                    logical_wildcard_type_owners.insert(normalized);
                }
            } else {
                let local_name = import
                    .local_name()
                    .map(str::to_string)
                    .unwrap_or_else(|| path.clone());
                logical_type_names.add_candidate(local_name, normalized, None, NAMESPACE_TIER, 192);
            }
        }
        // Every Scala compilation unit implicitly imports `scala.*`. Keep it
        // below the active package and every explicit/wildcard import, and bind
        // only physical source declarations so duplicate library replicas fail
        // closed in the same way as ordinary imports.
        for (simple, declaration) in types.package_types_in("scala").iter() {
            if scala_default_namespace_is_source_backed(simple) {
                names.add_type_declaration(simple.clone(), declaration, types, 1);
            }
        }
        for (simple, declaration) in types.package_objects_in(scala, "scala").iter() {
            if scala_default_namespace_is_source_backed(simple) {
                object_names.add_declaration(simple.clone(), declaration, 1);
            }
        }
        // Parser-established package scopes are visible from innermost to
        // outermost. A dotted package clause contributes only its complete
        // package; it does not invent parent-package bindings.
        for (index, package) in active_package_prefixes.iter().enumerate() {
            // Preserve Scala's ordinary lookup precedence: a wildcard import
            // beats declarations in another compilation unit of the active
            // package, an explicit import beats a wildcard, and declarations
            // in this compilation unit beat imports. Within the package
            // scopes established by nested/sequential package clauses, the
            // innermost package wins over its enclosing package.
            let package_priority = if package.is_empty() {
                0
            } else {
                64u8.saturating_add(index.min(63) as u8)
            };
            for (simple, decl) in types.package_types_in(package).iter() {
                let priority = if source_file == Some(decl.source()) {
                    224u8.saturating_add(index.min(30) as u8)
                } else {
                    package_priority
                };
                names.add_type_declaration(simple.clone(), decl, types, priority);
            }
            for (simple, decl) in types.package_objects_in(scala, package).iter() {
                let priority = if source_file == Some(decl.source()) {
                    224u8.saturating_add(index.min(30) as u8)
                } else {
                    package_priority
                };
                object_names.add_declaration(simple.clone(), decl, priority);
            }
            if include_members {
                for declaration in types.index.fqn_direct_children(package) {
                    if !declaration.is_function() && !declaration.is_field() {
                        continue;
                    }
                    let priority = if source_file == Some(declaration.source()) {
                        224u8.saturating_add(index.min(30) as u8)
                    } else {
                        package_priority
                    };
                    member_names.add_declaration(
                        declaration.identifier().to_string(),
                        &declaration,
                        priority,
                    );
                }
            }
        }

        let wildcard_environment = resolve_scala_wildcard_import_environment(
            imports,
            active_package_prefixes,
            |declaration_start_byte| {
                import_owner_scopes
                    .get(&declaration_start_byte)
                    .cloned()
                    .unwrap_or_default()
            },
            |candidate| ScalaWildcardOwnerFacts {
                package: types.index.package_container_exists(candidate),
                stable_singleton: types
                    .object_by_normalized_fqn(scala, &scala_normalized_fq_name(candidate))
                    .is_some(),
            },
        );
        for owner in &wildcard_environment.owners {
            if owner.is_singleton() {
                let normalized_owner = scala_normalized_fq_name(&owner.declaration_fqn());
                for (simple, decl) in types.nested_types_in(scala, &normalized_owner).iter() {
                    names.add_type_declaration(simple.clone(), decl, types, 128);
                }
                for (simple, decl) in types.nested_objects_in(scala, &normalized_owner).iter() {
                    object_names.add_declaration(simple.clone(), decl, 128);
                }
                if include_members && !wildcard_environment.ambiguous {
                    if let Some(declaration) =
                        types.object_by_normalized_fqn(scala, &normalized_owner)
                    {
                        for (visible_name, member) in types
                            .wildcard_member_declarations(scala, token, &declaration)
                            .iter()
                        {
                            member_names.add_declaration(visible_name.clone(), member, 128);
                        }
                        for (visible_name, member_fqn) in
                            types.exported_member_bindings(scala, token, &declaration)
                        {
                            member_names.add_candidate(
                                visible_name,
                                member_fqn,
                                None,
                                NAMESPACE_TIER,
                                128,
                            );
                        }
                    }
                    wildcard_extension_owners.push(normalized_owner);
                }
            } else {
                for child_package in types.index.child_packages(&owner.fqn) {
                    package_names.add_candidate(
                        scala_short_name_terminal_segment(&child_package),
                        child_package,
                        None,
                        NAMESPACE_TIER,
                        128,
                    );
                }
                for (simple, decl) in types.package_types_in(&owner.fqn).iter() {
                    names.add_type_declaration(simple.clone(), decl, types, 128);
                }
                for (simple, decl) in types.package_objects_in(scala, &owner.fqn).iter() {
                    object_names.add_declaration(simple.clone(), decl, 128);
                }
                if include_members && !wildcard_environment.ambiguous {
                    for declaration in types.index.fqn_direct_children(&owner.fqn) {
                        if declaration.is_function() || declaration.is_field() {
                            member_names.add_declaration(
                                declaration.identifier().to_string(),
                                &declaration,
                                128,
                            );
                        }
                    }
                    wildcard_extension_owners.push(owner.fqn.clone());
                }
            }
        }

        if include_members {
            // Resolve term and extension bindings one import at a time. An
            // ambiguous earlier wildcard must not erase a later, independent
            // wildcard import; it only contributes no bindings of its own.
            for import in imports.iter().filter(|import| import.is_wildcard) {
                let environment = resolve_scala_wildcard_import_environment(
                    std::slice::from_ref(import),
                    active_package_prefixes,
                    |declaration_start_byte| {
                        import_owner_scopes
                            .get(&declaration_start_byte)
                            .cloned()
                            .unwrap_or_default()
                    },
                    |candidate| ScalaWildcardOwnerFacts {
                        package: types.index.package_container_exists(candidate),
                        stable_singleton: types
                            .object_by_normalized_fqn(scala, &scala_normalized_fq_name(candidate))
                            .is_some(),
                    },
                );
                if environment.ambiguous {
                    continue;
                }
                for owner in &environment.owners {
                    if owner.is_singleton() {
                        let normalized_owner = scala_normalized_fq_name(&owner.declaration_fqn());
                        if let Some(declaration) =
                            types.object_by_normalized_fqn(scala, &normalized_owner)
                        {
                            for (visible_name, member) in types
                                .wildcard_member_declarations(scala, token, &declaration)
                                .iter()
                            {
                                member_names.add_declaration(visible_name.clone(), member, 128);
                            }
                            for (visible_name, member_fqn) in
                                types.exported_member_bindings(scala, token, &declaration)
                            {
                                member_names.add_candidate(
                                    visible_name,
                                    member_fqn,
                                    None,
                                    NAMESPACE_TIER,
                                    128,
                                );
                            }
                        }
                        wildcard_extension_owners.push(normalized_owner);
                    } else {
                        add_wildcard_member_bindings(
                            &mut member_names,
                            types.index.fqn_direct_children(&owner.fqn),
                        );
                        wildcard_extension_owners.push(owner.fqn.clone());
                    }
                }

                // Parser-recorded import paths omit Scala's physical `$`
                // separators. Bridge that logical path to one exact stable
                // type owner as well as its term companion: enum cases are
                // children of the enum type, not of an explicit companion
                // object such as Duration.Units.
                if let Some(path) = scala_import_path(import) {
                    let import_prefixes = import
                        .path
                        .as_ref()
                        .map(|path| path.lexical_prefixes.as_slice())
                        .filter(|prefixes| !prefixes.is_empty())
                        .unwrap_or(active_package_prefixes);
                    for candidate in scala_import_path_candidates(&path, import_prefixes) {
                        let normalized = scala_normalized_fq_name(&candidate);
                        let owner_declarations = types.index.by_normalized_fqn(&normalized);
                        let mut stable_owners = owner_declarations
                            .iter()
                            .filter(|unit| unit.is_class() && !unit.short_name().ends_with('$'))
                            .filter(|unit| types.type_is_stable_owner(scala, unit));
                        let Some(owner) = stable_owners.next() else {
                            continue;
                        };
                        if stable_owners.next().is_some() {
                            break;
                        }
                        add_wildcard_member_bindings(
                            &mut member_names,
                            types.index.fqn_direct_children(&owner.fq_name()),
                        );
                        wildcard_extension_owners.push(normalized);
                        break;
                    }
                }
            }
        }

        // Names an earlier explicit import binds in this file, so a later import
        // may be written through one: `import p.Implicits` makes `Implicits` a
        // visible root, and `import Implicits.request2Session` then names
        // `p.Implicits.request2Session`. Neither the package scopes nor the
        // lexical prefixes spell that owner, so the path resolves against this
        // map after both.
        let mut import_roots: HashMap<String, String> = HashMap::default();
        for import in imports {
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            if import.is_wildcard {
                continue;
            }
            let Some(tier) = types
                .explicit_import_tier(&path, active_package_prefixes)
                .or_else(|| {
                    let segments = import.path.as_ref().map(|path| path.segments.as_slice())?;
                    let [root, rest @ ..] = segments else {
                        return None;
                    };
                    if rest.is_empty() {
                        return None;
                    }
                    let bound = import_roots.get(root)?;
                    let candidate = std::iter::once(bound.as_str())
                        .chain(rest.iter().map(String::as_str))
                        .collect::<Vec<_>>()
                        .join(".");
                    types.explicit_import_tier(&candidate, &[])
                })
            else {
                continue;
            };
            if let Some(local) = import.local_name() {
                import_roots.insert(local.to_string(), tier.candidate.clone());
            }
            // `ImportInfo::local_name` is the shared `alias ?? identifier ??
            // tail-of-structured-path` desugar; scala's `identifier` is already
            // alias-resolved at construction, so this agrees with the old
            // `identifier ?? terminal-of(path)` fallback exactly.
            let local_name = import
                .local_name()
                .map(str::to_string)
                .unwrap_or_else(|| path.clone());
            if tier.declaration && tier.package {
                ambiguous_import_priorities.insert(local_name.clone(), 192);
            }
            if tier.declaration {
                let (type_declarations, mut object_declarations) =
                    types.explicit_import_type_declarations(&tier.candidate);
                if object_declarations.is_empty() {
                    object_declarations.extend(
                        type_declarations
                            .iter()
                            .filter(|declaration| {
                                types.type_accepts_object_roles(scala, declaration)
                            })
                            .cloned(),
                    );
                }
                for declaration in &type_declarations {
                    names.add_type_declaration(local_name.clone(), declaration, types, 192);
                }
                for declaration in &object_declarations {
                    object_names.add_declaration(local_name.clone(), declaration, 192);
                }
            }
            if tier.package {
                package_names.add_candidate(
                    local_name.clone(),
                    scala_normalized_fq_name(&tier.candidate),
                    None,
                    NAMESPACE_TIER,
                    192,
                );
            }
            let normalized = scala_normalized_fq_name(&tier.candidate);
            if include_members {
                let members =
                    types.importable_members_by_normalized_fqn(scala, &normalized, source_file);
                if !members.is_empty() {
                    for member in members {
                        member_names.add_declaration(local_name.clone(), &member, 192);
                    }
                    for method in types.direct_extension_method(scala, token, &normalized) {
                        direct_extension_methods
                            .entry(local_name.clone())
                            .or_default()
                            .push(method);
                    }
                }
            }
        }

        wildcard_extension_owners.sort();
        wildcard_extension_owners.dedup();
        for methods in direct_extension_methods.values_mut() {
            methods.sort_by(|left, right| left.declaration.cmp(&right.declaration));
            methods.dedup_by(|left, right| left.declaration == right.declaration);
        }

        Self {
            names,
            object_names,
            package_names,
            logical_type_names,
            logical_wildcard_type_owners,
            ambiguous_import_priorities,
            package_prefixes: active_package_prefixes.to_vec(),
            member_names,
            direct_extension_methods,
            wildcard_extension_owners,
        }
    }

    /// Resolve a type/object source name (stripping generics) to its fqn.
    pub fn resolve(&self, raw: &str) -> Option<String> {
        let simple = simple_type_name(raw)?;
        if self.import_collision_blocks(simple, self.names.priority(simple)) {
            return None;
        }
        self.names.resolve(simple)
    }

    fn resolve_logical(&self, raw: &str) -> Option<String> {
        let simple = simple_type_name(raw)?;
        if self.import_collision_blocks(simple, self.names.priority(simple)) {
            return None;
        }
        self.names.resolve_logical(simple)
    }

    fn logical_type_import_candidates(&self, raw: &str) -> Vec<String> {
        let Some(simple) = simple_type_name(raw) else {
            return Vec::new();
        };
        if self.logical_type_names.contains(simple) {
            return self
                .logical_type_names
                .resolve_logical(simple)
                .into_iter()
                .collect();
        }
        let mut candidates = self
            .logical_wildcard_type_owners
            .iter()
            .map(|owner| format!("{owner}.{simple}"))
            .collect::<Vec<_>>();
        candidates.sort();
        candidates.dedup();
        candidates
    }

    fn has_explicit_logical_type_import(&self, raw: &str) -> bool {
        simple_type_name(raw).is_some_and(|simple| self.logical_type_names.contains(simple))
    }

    pub fn type_binding_is_ambiguous(&self, raw: &str) -> bool {
        let Some(simple) = simple_type_name(raw) else {
            return false;
        };
        self.import_collision_blocks(simple, self.names.priority(simple))
            || self.names.is_ambiguous(simple)
    }

    pub fn object_binding_is_ambiguous(&self, raw: &str) -> bool {
        let Some(simple) = simple_type_name(raw) else {
            return false;
        };
        self.import_collision_blocks(simple, self.object_names.priority(simple))
            || self.object_names.is_ambiguous(simple)
    }

    pub fn resolve_object(&self, raw: &str) -> Option<String> {
        let simple = simple_type_name(raw)?;
        if self.import_collision_blocks(simple, self.object_names.priority(simple)) {
            return None;
        }
        self.object_names.resolve(simple)
    }

    fn resolve_qualified_type_root(
        &self,
        types: &ProjectTypes,
        raw: &str,
        mut lexical_objects: Vec<CodeUnit>,
    ) -> ScalaQualifiedTypeRootResolution {
        lexical_objects.sort();
        lexical_objects.dedup();
        if !lexical_objects.is_empty() {
            return ScalaQualifiedTypeRootResolution::Resolved(
                ScalaQualifiedTypeRootBinding::StableObjects(lexical_objects),
            );
        }
        let Some(simple) = simple_type_name(raw) else {
            return ScalaQualifiedTypeRootResolution::NoMatch;
        };
        let type_priority = self.names.priority(simple);
        let object_priority = self.object_names.priority(simple);
        let package_priority = self.package_names.priority(simple);
        let winner_priority = type_priority
            .into_iter()
            .chain(object_priority)
            .chain(package_priority)
            .max();
        if self.import_collision_blocks(simple, winner_priority) {
            return ScalaQualifiedTypeRootResolution::Ambiguous;
        }
        if let Some(winner) = winner_priority {
            if package_priority == Some(winner) && object_priority == Some(winner) {
                return ScalaQualifiedTypeRootResolution::Ambiguous;
            }
            if object_priority == Some(winner) {
                return self.object_names.resolve_declaration(simple);
            }
            if package_priority == Some(winner) {
                return self.package_names.resolve(simple).map_or(
                    ScalaQualifiedTypeRootResolution::Ambiguous,
                    |package| {
                        ScalaQualifiedTypeRootResolution::Resolved(
                            ScalaQualifiedTypeRootBinding::Package(package),
                        )
                    },
                );
            }
            return ScalaQualifiedTypeRootResolution::AuthoritativeMiss;
        }
        for candidate in scala_enclosing_package_root_candidates(&self.package_prefixes, simple) {
            if types.index.package_exists(&candidate) {
                return ScalaQualifiedTypeRootResolution::Resolved(
                    ScalaQualifiedTypeRootBinding::Package(candidate),
                );
            }
        }
        ScalaQualifiedTypeRootResolution::NoMatch
    }

    fn has_type_or_object_binding(&self, raw: &str) -> bool {
        simple_type_name(raw)
            .is_some_and(|simple| self.names.contains(simple) || self.object_names.contains(simple))
    }

    fn has_type_or_object_or_package_binding(&self, raw: &str) -> bool {
        simple_type_name(raw).is_some_and(|simple| {
            self.names.contains(simple)
                || self.object_names.contains(simple)
                || self.package_names.contains(simple)
        })
    }

    /// Resolve a source-visible member name imported directly from an owner.
    pub fn resolve_member(&self, raw: &str) -> Option<String> {
        let simple = simple_type_name(raw)?;
        if self.import_collision_blocks(simple, None) {
            return None;
        }
        self.member_names.resolve(simple)
    }

    pub fn visible_extension_methods(
        &self,
        scala: &dyn ScalaSource,
        token: QueryToken<'_>,
        types: &ProjectTypes,
        member: &str,
    ) -> Vec<ExtensionMethod> {
        if self.import_collision_blocks(member, None) {
            return Vec::new();
        }
        let mut methods = Vec::new();
        methods.extend(self.direct_extension_methods(member).iter().cloned());
        for owner in self.wildcard_extension_owners() {
            methods.extend(
                types
                    .extension_methods_for_owner_member(scala, token, owner, member)
                    .iter()
                    .cloned(),
            );
        }
        methods.sort_by(|left, right| left.declaration.cmp(&right.declaration));
        methods.dedup_by(|left, right| left.declaration == right.declaration);
        methods
    }

    fn direct_extension_methods(&self, member: &str) -> &[ExtensionMethod] {
        self.direct_extension_methods
            .get(member)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn wildcard_extension_owners(&self) -> &[String] {
        &self.wildcard_extension_owners
    }

    fn import_collision_blocks(&self, name: &str, winner_priority: Option<u8>) -> bool {
        self.ambiguous_import_priorities
            .get(name)
            .is_some_and(|collision_priority| {
                winner_priority.is_none_or(|priority| *collision_priority >= priority)
            })
    }
}

fn visible_imports_at_byte(
    imports: &[ImportInfo],
    reference_byte: Option<usize>,
) -> Vec<ImportInfo> {
    let Some(reference_byte) = reference_byte else {
        return imports.to_vec();
    };
    imports
        .iter()
        .filter(|import| scala_import_is_visible_at_byte(import, reference_byte))
        .cloned()
        .collect()
}

/// The package-qualified owner of `unit` — a pure segment pop on its own
/// structured `fq()` (shared with `CodeUnitIndex::parent_of`), not a re-guess of
/// where the legacy short_name string's last `.` falls plus a manual
/// package re-qualification (this function's old body did exactly that
/// reconstruction by hand).
fn owner_fqn(unit: &CodeUnit) -> Option<String> {
    brokk_bifrost_core::analyzer::default_parent_fq_name(unit)
}

enum PhysicalCallableTargets {
    NoCandidates,
    Unique(Vec<CodeUnit>),
    Ambiguous,
}

impl PhysicalCallableTargets {
    fn into_unique(self) -> Vec<CodeUnit> {
        match self {
            Self::Unique(targets) => targets,
            Self::NoCandidates | Self::Ambiguous => Vec::new(),
        }
    }
}

pub fn is_package_level_type(unit: &CodeUnit) -> bool {
    !unit.short_name().contains('.')
}

fn method_arities_compatible(method: Option<usize>, ancestor: Option<usize>) -> bool {
    method.is_none() || ancestor.is_none() || method == ancestor
}

fn callable_call_shape_matches(
    facts: &CallableFacts,
    alternatives: &[CallableAlternative],
    call_arities: Option<&[usize]>,
    fallback_role: ScalaCallableRole,
    site_role: ScalaCallableSiteRole,
    unique_callable: bool,
) -> bool {
    let actual = call_arities.map(ScalaCallSiteShape::ordinary);
    let fallback_shape;
    if alternatives.is_empty() {
        fallback_shape = facts
            .callable_arity
            .or_else(|| facts.arity.map(CallableArity::exact))
            .map(|arity| vec![ScalaCallableParameterList::explicit(arity)])
            .unwrap_or_default();
        return scala_callable_alternative_matches(
            fallback_role,
            &fallback_shape,
            ScalaDeclaredResult::UNDECLARED,
            actual.as_ref(),
            site_role,
            unique_callable,
        );
    }
    alternatives.iter().any(|alternative| {
        scala_callable_alternative_matches(
            alternative.role,
            &alternative.shape,
            alternative.result,
            actual.as_ref(),
            site_role,
            unique_callable,
        )
    })
}

fn ordinary_callable_shape_matches(
    declared: &CallableAlternative,
    call_arities: Option<&[usize]>,
    unique_callable: bool,
) -> bool {
    let actual = call_arities.map(ScalaCallSiteShape::ordinary);
    scala_callable_shape_matches(
        &declared.shape,
        declared.result,
        actual.as_ref(),
        ScalaCallableUsePolicy::OrdinaryMethod,
        unique_callable,
    )
}

fn method_key(fqn: &str, arity: Option<usize>) -> String {
    match arity {
        Some(arity) => format!("{fqn}#{arity}"),
        None => fqn.to_string(),
    }
}

/// The leading simple name of a (possibly generic/qualified) type text.
fn simple_type_name(type_text: &str) -> Option<&str> {
    type_text
        .split(['[', '(', '{', '.', ' '])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

/// Build the whole Scala `caller -> callee` edge set in a single inverted pass
/// over the workspace.
/// `nodes`/`keep_file` mirror the Go builder.
struct ScalaEdgeSink<'a> {
    input: &'a FileEdgeScanInput<'a>,
    edges: PerFileEdges,
    scala: &'a dyn ScalaSource,
    types: &'a ProjectTypes,
    imports: &'a [ImportInfo],
}

impl ScalaReferenceSink for ScalaEdgeSink<'_> {
    fn may_match_name(&self, name: &str) -> bool {
        self.input.may_match_terminal(name)
            || self
                .imports
                .iter()
                .filter(|import| import.alias.as_deref() == Some(name))
                .any(|import| {
                    import.path.as_ref().is_none_or(|path| {
                        path.segments
                            .last()
                            .is_none_or(|terminal| self.input.may_match_terminal(terminal))
                    })
                })
    }

    fn may_match_import_terminal(&self, name: &str) -> bool {
        self.may_match_name(name)
    }

    fn record(
        &mut self,
        target: ScalaResolvedReference,
        role: ScalaReferenceRole,
        reference_kind: UsageReferenceKind,
        hit_kind: UsageHitKind,
        start: usize,
        end: usize,
    ) {
        // A same-owner (self/this receiver, implicit-this, or own-object) call is
        // recorded as UNPROVEN inbound, never a proven caller->callee edge, so a
        // method reachable only through same-owner calls reads INCONCLUSIVE for
        // dead-code — uniform with Rust and the other landed languages (#1138).
        let unproven_target = match &target {
            ScalaResolvedReference::Exact(unit) => unit.fq_name(),
            ScalaResolvedReference::Logical(fqn) => fqn.clone(),
        };
        route_same_owner(
            self,
            hit_kind == UsageHitKind::SelfReceiver,
            move |sink| {
                sink.edges
                    .record_unproven(sink.input, unproven_target, start, end);
            },
            move |sink| {
                if matches!(
                    role,
                    ScalaReferenceRole::CompanionApplication
                        | ScalaReferenceRole::CompanionExtractor
                        | ScalaReferenceRole::CompanionValue
                ) && let ScalaResolvedReference::Exact(callable) = &target
                    && let Some(owner) = sink.types.exact_structural_parent(sink.scala, callable)
                {
                    let companions = if owner.short_name().ends_with('$') {
                        vec![owner]
                    } else {
                        sink.types.exact_companion_objects(sink.scala, &owner)
                    };
                    if let [companion] = companions.as_slice() {
                        sink.edges.record_kind(
                            sink.input,
                            companion.fq_name(),
                            reference_kind,
                            start,
                            end,
                        );
                    }
                }
                let target = match target {
                    ScalaResolvedReference::Exact(unit) => unit.fq_name(),
                    ScalaResolvedReference::Logical(fqn) => fqn,
                };
                sink.edges
                    .record_kind(sink.input, target, reference_kind, start, end);
            },
        );
    }

    fn record_with_caller(
        &mut self,
        caller: String,
        target: ScalaResolvedReference,
        role: ScalaReferenceRole,
        reference_kind: UsageReferenceKind,
        _hit_kind: UsageHitKind,
        start: usize,
        end: usize,
    ) {
        if role == ScalaReferenceRole::Override
            && let ScalaResolvedReference::Exact(target) = &target
            && self
                .scala
                .structural_parent_of(target)
                .is_some_and(|owner| !self.types.is_scala_trait_declaration(self.scala, &owner))
        {
            return;
        }
        let target = match target {
            ScalaResolvedReference::Exact(unit) => unit.fq_name(),
            ScalaResolvedReference::Logical(fqn) => fqn,
        };
        self.edges
            .record_with_caller_kind(self.input, caller, target, reference_kind, start, end);
    }

    fn record_unproven_name(&mut self, name: &str, start: usize, end: usize) {
        self.edges
            .record_unproven_name(self.input, name, start, end);
    }

    fn record_import_name(
        &mut self,
        imports: &[ImportInfo],
        active_package: &str,
        name: &str,
        start: usize,
        end: usize,
    ) {
        if !self.may_match_name(name) {
            return;
        }
        let package_prefixes = if active_package.is_empty() {
            Vec::new()
        } else {
            vec![active_package.to_string()]
        };
        let environment = resolve_scala_wildcard_import_environment(
            imports,
            &package_prefixes,
            |_| Vec::new(),
            |candidate| ScalaWildcardOwnerFacts {
                package: self.types.index.package_container_exists(candidate),
                stable_singleton: self
                    .types
                    .object_by_normalized_fqn(self.scala, &scala_normalized_fq_name(candidate))
                    .is_some(),
            },
        );
        let mut recorded = HashSet::default();
        for owner in environment.owners {
            if !owner.is_singleton() || scala_short_name_terminal_segment(&owner.fqn) != name {
                continue;
            }
            let normalized = scala_normalized_fq_name(&owner.fqn);
            let Some(target) = self
                .types
                .unique_object_by_normalized_fqn(self.scala, &normalized)
            else {
                continue;
            };
            if !recorded.insert(target.fq_name()) {
                continue;
            }
            self.record(
                ScalaResolvedReference::Exact(target),
                ScalaReferenceRole::StableObject,
                UsageReferenceKind::Other,
                UsageHitKind::Import,
                start,
                end,
            );
        }
    }
}

/// Walk one already-parsed Scala file for the whole-workspace inverted build.
///
/// The fan-out around this stays in `brokk-bifrost-analysis`:
/// `build_edge_output` and `parse_source_and_collect_with_declarations` are the
/// shared, language-agnostic driver, and only this per-file walk is Scala's.
/// The caller supplies the file's `ScalaFileFacts` (the same record
/// [`ProjectTypes`] holds) and the class-range index it built from them, both
/// of which the driver needs anyway to build the file's declarations.
pub fn scan_edge_file(
    scala: &dyn ScalaSource,
    token: QueryToken<'_>,
    types: &ProjectTypes,
    file: &ProjectFile,
    state: &ScalaFileFacts,
    class_ranges: ClassRangeIndex,
    input: &FileEdgeScanInput<'_>,
) -> PerFileEdges {
    let mut sink = ScalaEdgeSink {
        input,
        edges: PerFileEdges::default(),
        scala,
        types,
        imports: &state.imports,
    };
    let resolver = Arc::new(NameResolver::for_file_with_facts(
        scala,
        token,
        Some(file),
        Some(&state.package_name),
        &[],
        types,
    ));
    let import_owner_scopes =
        scala_import_owner_scopes(&state.imports, &class_ranges, scala, types);
    let mut ctx = ScalaScan {
        scala,
        token,
        workspace: None,
        source: input.source,
        source_file: file,
        imports: &state.imports,
        active_package: state.package_name.clone(),
        import_contexts: ScalaImportContextIndex::new(&state.imports, input.root().end_byte()),
        import_context_cursor: 0,
        package_contexts: ScalaPackageContextIndex::new(input.root(), input.source),
        package_context_cursor: 0,
        resolver,
        active_resolver_key: None,
        resolver_contexts: HashMap::default(),
        import_owner_scopes,
        types,
        class_ranges,
        sink: &mut sink,
        cancellation: None,
        invocation_callables: HashMap::default(),
    };
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    walk(input.root(), token, &mut ctx, &mut bindings);
    sink.edges
}

/// Scan one caller-supplied Scala file through the same structured resolver used
/// by the whole-workspace graph, without constructing or hydrating that graph.
/// The caller supplies the exact-target sink and owns file eligibility.
///
/// `workspace` is the dispatching, all-language definition view (see
/// [`ScalaWorkspaceSource`]). The walk consults it only to give a receiver or
/// type whose written name has no Scala declaration one logical chance through
/// the realm before giving up on it (#1859); per-file `ScalaSource` state is
/// never used for that (#1805).
#[allow(clippy::too_many_arguments)]
pub fn scan_scala_query_file(
    scala: &dyn ScalaSource,
    token: QueryToken<'_>,
    types: &ProjectTypes,
    analyzer: &dyn CodeUnitIndex,
    workspace: &dyn ScalaWorkspaceSource,
    file: &ProjectFile,
    source: &str,
    sink: &mut dyn ScalaReferenceSink,
    cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
) -> bool {
    if cancellation.is_some_and(brokk_bifrost_core::cancellation::CancellationToken::is_cancelled) {
        return false;
    }
    let Some(tree) = parse_scala_query_file(scala, source) else {
        return false;
    };
    let class_ranges = ClassRangeIndex::build(analyzer, file);
    scan_scala_query_tree(
        scala,
        token,
        types,
        workspace,
        file,
        source,
        &tree,
        class_ranges,
        sink,
        cancellation,
    )
}

pub fn parse_scala_query_file(scala: &dyn ScalaSource, source: &str) -> Option<Tree> {
    #[cfg(not(any(test, feature = "test-support")))]
    let _ = scala;
    if source.is_empty() {
        return None;
    }
    let mut parser = Parser::new();
    if parser
        .set_language(&crate::scala::language::LANGUAGE.into())
        .is_err()
    {
        return None;
    }
    let tree = parser.parse(source, None)?;
    #[cfg(any(test, feature = "test-support"))]
    scala.record_query_parse();
    Some(tree)
}

#[allow(clippy::too_many_arguments)]
pub fn scan_scala_query_tree(
    scala: &dyn ScalaSource,
    token: QueryToken<'_>,
    types: &ProjectTypes,
    workspace: &dyn ScalaWorkspaceSource,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    class_ranges: ClassRangeIndex,
    sink: &mut dyn ScalaReferenceSink,
    cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
) -> bool {
    if cancellation.is_some_and(brokk_bifrost_core::cancellation::CancellationToken::is_cancelled) {
        return false;
    }
    let Some(state) = types.bulk_file_state(file) else {
        return false;
    };
    let package = state.package_name.clone();
    let imports = &state.imports;
    sink.register_imports(imports);
    let resolver = Arc::new(NameResolver::for_file_with_facts(
        scala,
        token,
        Some(file),
        Some(&package),
        &[],
        types,
    ));
    let import_owner_scopes = scala_import_owner_scopes(imports, &class_ranges, scala, types);
    let mut ctx = ScalaScan {
        scala,
        token,
        workspace: Some(workspace),
        source,
        source_file: file,
        imports,
        active_package: package,
        import_contexts: ScalaImportContextIndex::new(imports, tree.root_node().end_byte()),
        import_context_cursor: 0,
        package_contexts: ScalaPackageContextIndex::new(tree.root_node(), source),
        package_context_cursor: 0,
        resolver,
        active_resolver_key: None,
        resolver_contexts: HashMap::default(),
        import_owner_scopes,
        types,
        class_ranges,
        sink,
        cancellation,
        invocation_callables: HashMap::default(),
    };
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    #[cfg(any(test, feature = "test-support"))]
    scala.record_query_walk();
    walk(tree.root_node(), token, &mut ctx, &mut bindings);
    true
}

struct ScalaScan<'a, 'b> {
    scala: &'a dyn ScalaSource,
    /// Proof that a request scope is open: this scan reaches import-tier
    /// storage through `scala` (issue #2423).
    token: QueryToken<'a>,
    /// The all-language definition view (#1859). Present only on the query
    /// path: the edge build runs inside the Scala analyzer's own indexing and
    /// has no merged index to consult, and its behavior must not change here.
    workspace: Option<&'a dyn ScalaWorkspaceSource>,
    source: &'a str,
    source_file: &'a ProjectFile,
    imports: &'a [ImportInfo],
    active_package: String,
    import_contexts: ScalaImportContextIndex,
    import_context_cursor: usize,
    package_contexts: ScalaPackageContextIndex,
    package_context_cursor: usize,
    resolver: Arc<NameResolver>,
    active_resolver_key: Option<(Vec<String>, Vec<usize>)>,
    resolver_contexts: HashMap<(Vec<String>, Vec<usize>), Arc<NameResolver>>,
    import_owner_scopes: HashMap<usize, Vec<String>>,
    types: &'a ProjectTypes,
    class_ranges: ClassRangeIndex,
    sink: &'a mut dyn ScalaReferenceSink,
    cancellation: Option<&'b brokk_bifrost_core::cancellation::CancellationToken>,
    /// Callables this scan proved for each invocation, keyed by the id of the
    /// invocation's terminal callee-name node. The walk enters an invocation
    /// before its `arguments`, so a named-argument label reads the callee that
    /// the ordinary call resolution already selected instead of resolving the
    /// owner a second time through a narrower path. An invocation whose callee
    /// stayed unproven has no entry, which keeps labels fail-closed.
    invocation_callables: HashMap<usize, Vec<CodeUnit>>,
}

impl ScalaScan<'_, '_> {
    fn activate_import_context(&mut self, token: QueryToken<'_>, node: Node<'_>) {
        let visible_imports = self
            .import_contexts
            .advance_to(node.start_byte(), &mut self.import_context_cursor);
        let visible_packages = self
            .package_contexts
            .advance_to(node.start_byte(), &mut self.package_context_cursor);
        if self
            .active_resolver_key
            .as_ref()
            .is_some_and(|(packages, imports)| {
                packages.as_slice() == visible_packages && imports.as_slice() == visible_imports
            })
        {
            return;
        }
        let key = (visible_packages.to_vec(), visible_imports.to_vec());
        if let Some(resolver) = self.resolver_contexts.get(&key) {
            self.resolver = resolver.clone();
            self.active_package = key.0.last().cloned().unwrap_or_default();
            self.active_resolver_key = Some(key);
            return;
        }
        let imports = key
            .1
            .iter()
            .filter_map(|index| self.imports.get(*index).cloned())
            .collect::<Vec<_>>();
        let resolver = Arc::new(
            NameResolver::for_file_with_package_context_and_owner_scopes(
                self.scala,
                token,
                Some(self.source_file),
                &key.0,
                &imports,
                self.types,
                &self.import_owner_scopes,
            ),
        );
        self.resolver_contexts.insert(key.clone(), resolver.clone());
        self.resolver = resolver;
        self.active_package = key.0.last().cloned().unwrap_or_default();
        self.active_resolver_key = Some(key);
    }

    /// The fqn of the smallest class/object declaration containing `byte`.
    fn enclosing_class(&self, byte: usize) -> Option<&str> {
        self.class_ranges.enclosing(byte)
    }

    fn enclosing_class_unit(&self, byte: usize) -> Option<&CodeUnit> {
        self.class_ranges.enclosing_unit(byte)
    }

    /// The `UsageHitKind` a callable reference at `node` targeting `callee`
    /// carries under the same-owner policy (#1014 facet B / #1138).
    ///
    /// A method call whose receiver denotes the current instance / own object —
    /// explicit `this.m()`, an implicit bare `m()` resolved to an own or
    /// inherited template member, or `Obj.m()` from within `Obj` — is a
    /// self/this receiver. `super.m()` and a call through a different variable
    /// (even one of the same type) stay external references.
    fn callable_reference_hit_kind(&self, node: Node<'_>, callee: &CodeUnit) -> UsageHitKind {
        if self.callable_reference_is_same_owner(node, callee) {
            UsageHitKind::SelfReceiver
        } else {
            UsageHitKind::Reference
        }
    }

    fn callable_reference_is_same_owner(&self, node: Node<'_>, callee: &CodeUnit) -> bool {
        // Only an actual invocation is a self/this-receiver *call*. A bare method
        // *value* (eta-expansion / a method captured as a function value) is a
        // genuine usage even within the owning type and stays external, matching
        // C#'s method-group-value rule (#1014).
        if !scala_reference_is_invoked(node) {
            return false;
        }
        match callable_receiver_value(node) {
            Some(receiver) => {
                let text = node_text(receiver, self.source).trim();
                if receiver.kind() == "this" || text == "this" {
                    // Explicit `this.m()` — the enclosing instance.
                    true
                } else if text == "super" {
                    // `super.m()` is a deliberate up-call: external, uniform with
                    // every landed language.
                    false
                } else {
                    // Own-object `Obj.m()` from within `Obj`.
                    self.receiver_names_enclosing_own_object(node.start_byte(), text, callee)
                }
            }
            // Bare `m()` — implicit-this iff the callee is an (own or inherited)
            // member of the enclosing template, not an imported free function.
            None => self.callee_owned_by_enclosing_template(node.start_byte(), callee),
        }
    }

    /// The class/object templates enclosing `byte`, innermost first, walking the
    /// structural owner chain. Mirrors
    /// [`scala_enclosing_template_owner_fq_names`] but keeps the `CodeUnit`
    /// identities for exact owner comparison.
    fn enclosing_template_owners(&self, byte: usize) -> Vec<CodeUnit> {
        let mut owners = Vec::new();
        let mut current = self.class_ranges.enclosing_unit(byte).cloned();
        let mut seen = HashSet::default();
        while let Some(template) = current {
            if !seen.insert(template.clone()) {
                break;
            }
            current = self.types.exact_structural_parent(self.scala, &template);
            if template.is_class() {
                owners.push(template);
            }
        }
        owners
    }

    /// Whether `callee` is declared directly by the *innermost* enclosing template
    /// at `byte` — the implicit-`this` case for a bare call: `m()` resolving to a
    /// member of the current instance's own declaration.
    ///
    /// This deliberately compares the enclosing template against the callee's
    /// owner by equality (the uniform enclosing-template == owner rule). A bare
    /// name resolving to an *inherited* member (owned by a supertype), an *outer*
    /// lexical scope's member (a different, enclosing instance), or an imported
    /// free function is a call across a declaration/instance boundary and stays an
    /// external reference — genuine cross-declaration demand for the callee.
    fn callee_owned_by_enclosing_template(&self, byte: usize, callee: &CodeUnit) -> bool {
        let Some(owner) = self.types.exact_structural_parent(self.scala, callee) else {
            return false;
        };
        self.class_ranges
            .enclosing_unit(byte)
            .is_some_and(|template| template.fq_name() == owner.fq_name())
    }

    /// Whether `receiver_text` names an enclosing singleton object that declares
    /// `callee` — the own-object static-style call `Obj.m()` from within `Obj`.
    /// A same-typed local variable has a different name and is excluded; a sibling
    /// object is not an enclosing owner and is excluded.
    fn receiver_names_enclosing_own_object(
        &self,
        byte: usize,
        receiver_text: &str,
        callee: &CodeUnit,
    ) -> bool {
        let Some(owner) = self.types.exact_structural_parent(self.scala, callee) else {
            return false;
        };
        // Only a singleton object can be a named same-owner receiver: an instance
        // method is never reachable through a bare *type* name.
        if !owner.short_name().ends_with('$') || scala_simple_type_name(&owner) != receiver_text {
            return false;
        }
        let owner_fqn = owner.fq_name();
        self.enclosing_template_owners(byte)
            .iter()
            .any(|template| template.fq_name() == owner_fqn)
    }

    fn exact_lexically_visible_type(
        &self,
        token: QueryToken<'_>,
        node: Node<'_>,
    ) -> ScalaTypeNamespaceResolution {
        let lookup_node = scala_qualified_type_root(node);
        let segments = scala_type_lookup_segments(lookup_node, self.source);
        let resolution = self.exact_lexically_visible_type_root(token, node);
        if segments.len() == 1 {
            return resolution;
        }
        match resolution {
            ScalaTypeNamespaceResolution::AuthoritativeMiss
            | ScalaTypeNamespaceResolution::Ambiguous(_) => resolution,
            ScalaTypeNamespaceResolution::NoMatch | ScalaTypeNamespaceResolution::Resolved(_) => {
                ScalaTypeNamespaceResolution::NoMatch
            }
        }
    }

    fn exact_lexically_visible_type_root(
        &self,
        token: QueryToken<'_>,
        node: Node<'_>,
    ) -> ScalaTypeNamespaceResolution {
        let lookup_node = scala_qualified_type_root(node);
        if scala_type_reference_is_singleton(lookup_node) {
            return ScalaTypeNamespaceResolution::NoMatch;
        }
        let segments = scala_type_lookup_segments(lookup_node, self.source);
        let Some(root_name) = segments.first() else {
            return ScalaTypeNamespaceResolution::NoMatch;
        };
        if let Some(binding) =
            scala_nearest_unindexed_type_binding(self.source, lookup_node, root_name)
        {
            return match binding {
                ScalaUnindexedTypeBinding::Authoritative => {
                    ScalaTypeNamespaceResolution::AuthoritativeMiss
                }
                ScalaUnindexedTypeBinding::AnonymousRefinement(instance) => self
                    .exact_type_member_before_anonymous_binding(
                        token,
                        lookup_node,
                        instance,
                        root_name,
                    ),
            };
        }
        let mut owners = Vec::new();
        let mut current = self.class_ranges.enclosing_unit(node.start_byte()).cloned();
        while let Some(owner) = current {
            current = self.types.exact_structural_parent(self.scala, &owner);
            if owner.is_class() {
                owners.push(owner);
            }
        }
        let lexical = self.types.exact_lexical_type_namespace(
            self.scala,
            self.token,
            owners.iter().cloned(),
            root_name,
            false,
        );
        match lexical {
            ScalaTypeNamespaceResolution::NoMatch => {}
            other => return other,
        }
        if self.imports.iter().any(|import| {
            !import.is_wildcard
                && scala_import_is_visible_at_byte(import, lookup_node.start_byte())
                && import.local_name() == Some(root_name)
        }) {
            return ScalaTypeNamespaceResolution::NoMatch;
        }
        for owner in owners {
            let companions = self.types.exact_companion_objects(self.scala, &owner);
            if companions.is_empty() {
                continue;
            }
            match self
                .types
                .exact_lexical_type_namespace(self.scala, self.token, companions, root_name, false)
            {
                ScalaTypeNamespaceResolution::NoMatch => {}
                other => return other,
            }
        }
        ScalaTypeNamespaceResolution::NoMatch
    }

    /// Resolve exact indexed type-member tiers encountered before an outer
    /// anonymous refinement binding. Intervening anonymous constructed bases
    /// and named templates both have higher precedence than the outer alias.
    fn exact_type_member_before_anonymous_binding(
        &self,
        token: QueryToken<'_>,
        lookup_node: Node<'_>,
        binding_instance: Node<'_>,
        name: &str,
    ) -> ScalaTypeNamespaceResolution {
        let mut current = Some(lookup_node);
        while let Some(node) = current {
            if node.kind() == "template_body" {
                if let Some(instance) = scala_anonymous_instance_for_template(node) {
                    let Some(owner) =
                        self.constructed_type_declaration_for_boundary(token, instance)
                    else {
                        return ScalaTypeNamespaceResolution::AuthoritativeMiss;
                    };
                    if instance != binding_instance {
                        match self.types.exact_lexical_type_namespace(
                            self.scala,
                            self.token,
                            std::iter::once(owner),
                            name,
                            false,
                        ) {
                            ScalaTypeNamespaceResolution::Resolved(member) => {
                                return ScalaTypeNamespaceResolution::Resolved(member);
                            }
                            ScalaTypeNamespaceResolution::NoMatch => {
                                current = node.parent();
                                continue;
                            }
                            ScalaTypeNamespaceResolution::AuthoritativeMiss
                            | ScalaTypeNamespaceResolution::Ambiguous(_) => {
                                return ScalaTypeNamespaceResolution::AuthoritativeMiss;
                            }
                        }
                    }
                    match self
                        .types
                        .stable_type_member_for_owner_unit(self.scala, token, &owner, name)
                    {
                        FieldResolution::Resolved(member)
                            if self.types.is_type_alias(self.scala, &member.declaration) =>
                        {
                            return ScalaTypeNamespaceResolution::Resolved(member.declaration);
                        }
                        FieldResolution::Resolved(_) | FieldResolution::NoMatch => {
                            return ScalaTypeNamespaceResolution::AuthoritativeMiss;
                        }
                        FieldResolution::Unresolved => {
                            return ScalaTypeNamespaceResolution::AuthoritativeMiss;
                        }
                    }
                } else if let Some(named_owner) = scala_named_template_owner(node) {
                    let Some(owner) = self
                        .class_ranges
                        .unit_for_exact_span(named_owner.start_byte(), named_owner.end_byte())
                        .cloned()
                    else {
                        return ScalaTypeNamespaceResolution::AuthoritativeMiss;
                    };
                    match self.types.exact_lexical_type_namespace(
                        self.scala,
                        self.token,
                        std::iter::once(owner),
                        name,
                        false,
                    ) {
                        ScalaTypeNamespaceResolution::Resolved(member) => {
                            return ScalaTypeNamespaceResolution::Resolved(member);
                        }
                        ScalaTypeNamespaceResolution::NoMatch => {}
                        ScalaTypeNamespaceResolution::AuthoritativeMiss
                        | ScalaTypeNamespaceResolution::Ambiguous(_) => {
                            return ScalaTypeNamespaceResolution::AuthoritativeMiss;
                        }
                    }
                }
            }
            current = node.parent();
        }
        ScalaTypeNamespaceResolution::AuthoritativeMiss
    }

    /// Resolve an anonymous base which may itself be a nested type inherited
    /// from a surrounding anonymous base (for example `Metric.UnsafeAPI`).
    fn constructed_type_declaration_for_boundary(
        &self,
        token: QueryToken<'_>,
        instance: Node<'_>,
    ) -> Option<CodeUnit> {
        let mut templates = Vec::new();
        let mut current = instance.parent();
        while let Some(node) = current {
            if node.kind() == "template_body" {
                templates.push(node);
            }
            current = node.parent();
        }
        templates.reverse();

        let mut exact_owners = Vec::new();
        for template in templates {
            if let Some(outer_instance) = scala_anonymous_instance_for_template(template) {
                let owner = self.constructed_type_declaration_against_owners(
                    token,
                    outer_instance,
                    &exact_owners,
                )?;
                exact_owners.push(owner);
            } else if let Some(named_owner) = scala_named_template_owner(template) {
                let owner = self
                    .class_ranges
                    .unit_for_exact_span(named_owner.start_byte(), named_owner.end_byte())
                    .cloned()?;
                exact_owners.push(owner);
            }
        }
        self.constructed_type_declaration_against_owners(token, instance, &exact_owners)
    }

    fn constructed_type_declaration_against_owners(
        &self,
        token: QueryToken<'_>,
        instance: Node<'_>,
        exact_owners_outer_first: &[CodeUnit],
    ) -> Option<CodeUnit> {
        let type_node = constructed_type_node(instance)?;
        let path = scala_type_lookup_segments(type_node, self.source);
        let [name] = path.as_slice() else {
            return constructed_type_declaration(instance, token, self);
        };
        let local_binding = scala_nearest_unindexed_type_binding(self.source, type_node, name);
        if local_binding.is_some() {
            return None;
        }

        for owner in exact_owners_outer_first.iter().rev() {
            match self.types.exact_lexical_type_namespace(
                self.scala,
                self.token,
                std::iter::once(owner.clone()),
                name,
                false,
            ) {
                ScalaTypeNamespaceResolution::Resolved(target) => {
                    return exact_constructed_type_target(type_node, token, target, name, self);
                }
                ScalaTypeNamespaceResolution::NoMatch => {}
                ScalaTypeNamespaceResolution::AuthoritativeMiss
                | ScalaTypeNamespaceResolution::Ambiguous(_) => return None,
            }
        }
        constructed_type_declaration(instance, token, self)
    }

    fn visible_type(&self, token: QueryToken<'_>, node: Node<'_>, name: &str) -> Option<String> {
        match self.exact_lexically_visible_type(token, node) {
            ScalaTypeNamespaceResolution::Resolved(declaration) => Some(declaration.fq_name()),
            ScalaTypeNamespaceResolution::NoMatch => self.resolver.resolve(name),
            ScalaTypeNamespaceResolution::AuthoritativeMiss
            | ScalaTypeNamespaceResolution::Ambiguous(_) => None,
        }
    }

    fn visible_type_reference(
        &self,
        token: QueryToken<'_>,
        node: Node<'_>,
        name: &str,
    ) -> Option<ScalaResolvedReference> {
        match self.exact_lexically_visible_type(token, node) {
            ScalaTypeNamespaceResolution::Resolved(declaration) => {
                Some(ScalaResolvedReference::Exact(declaration))
            }
            // Single-unit by contract: this produces one
            // `ScalaResolvedReference`, and a cross-built replica falls
            // through to the `Logical` arm below, whose catalog bucket carries
            // every family member's target id since #2021. Migrating this to
            // the plural resolver would duplicate that routing, not extend it.
            ScalaTypeNamespaceResolution::NoMatch => self
                .resolver
                .resolve_unit(name)
                .map(ScalaResolvedReference::Exact)
                .or_else(|| {
                    self.resolver
                        .resolve(name)
                        .map(ScalaResolvedReference::Logical)
                }),
            ScalaTypeNamespaceResolution::AuthoritativeMiss
            | ScalaTypeNamespaceResolution::Ambiguous(_) => None,
        }
    }

    fn lexically_visible_object(&self, byte: usize, name: &str) -> Option<String> {
        self.lexically_visible_object_unit(byte, name)
            .map(|unit| unit.fq_name())
    }

    fn visible_object_reference(&self, byte: usize, name: &str) -> Option<ScalaResolvedReference> {
        self.lexically_visible_object_unit(byte, name)
            .map(ScalaResolvedReference::Exact)
            .or_else(|| {
                self.resolver
                    .resolve_object_unit(name)
                    .map(ScalaResolvedReference::Exact)
            })
            .or_else(|| {
                self.resolver
                    .resolve_object(name)
                    .map(ScalaResolvedReference::Logical)
            })
    }

    fn lexically_visible_object_unit(&self, byte: usize, name: &str) -> Option<CodeUnit> {
        self.class_ranges.find_in_enclosing_units(byte, |owner| {
            if self.types.type_is_stable_owner(self.scala, owner)
                && scala_simple_type_name(owner) == name
            {
                Some(owner.clone())
            } else {
                self.types
                    .exact_nested_object_for_owner(self.scala, owner, name)
            }
        })
    }

    /// The template an owner-qualified `X.this` names (#2082).
    ///
    /// Scala admits the qualifier only when it spells a template enclosing the
    /// site, so the reference is that declaration and nothing else can supply
    /// it. A spelling that names no enclosing template stays unrecorded.
    fn enclosing_template_named(&self, byte: usize, name: &str) -> Option<CodeUnit> {
        self.class_ranges.find_in_enclosing_units(byte, |owner| {
            (scala_simple_type_name(owner) == name).then(|| owner.clone())
        })
    }

    fn record_with_caller(&mut self, caller: String, callee: CodeUnit, node: Node<'_>) {
        self.sink.record_with_caller(
            caller,
            ScalaResolvedReference::Exact(callee),
            ScalaReferenceRole::Override,
            classify_reference_node(node),
            UsageHitKind::OverrideDeclaration,
            node.start_byte(),
            node.end_byte(),
        );
    }

    /// Remember `callee` as a proven target of the invocation whose terminal
    /// callee-name node is `node`. Named-argument labels inside that
    /// invocation's arguments resolve their parameter owner from this record.
    fn register_invocation_callable(&mut self, callee: &CodeUnit, node: Node<'_>) {
        self.invocation_callables
            .entry(node.id())
            .or_default()
            .push(callee.clone());
    }

    fn record_exact(&mut self, callee: CodeUnit, role: ScalaReferenceRole, node: Node<'_>) {
        let hit_kind = if role == ScalaReferenceRole::Callable {
            self.register_invocation_callable(&callee, node);
            self.callable_reference_hit_kind(node, &callee)
        } else {
            UsageHitKind::Reference
        };
        self.sink.record(
            ScalaResolvedReference::Exact(callee),
            role,
            classify_reference_node(node),
            hit_kind,
            node.start_byte(),
            node.end_byte(),
        );
    }

    fn record_exact_import(&mut self, callee: CodeUnit, role: ScalaReferenceRole, node: Node<'_>) {
        self.sink.record(
            ScalaResolvedReference::Exact(callee),
            role,
            UsageReferenceKind::Other,
            UsageHitKind::Import,
            node.start_byte(),
            node.end_byte(),
        );
    }

    fn record_exact_owner_member(
        &mut self,
        owner: CodeUnit,
        member: &str,
        role: ScalaReferenceRole,
        node: Node<'_>,
    ) {
        self.sink.record_exact_owner_member(
            owner,
            member,
            role,
            classify_reference_node(node),
            UsageHitKind::Reference,
            node.start_byte(),
            node.end_byte(),
        );
    }

    /// Emit a member reference whose owner is a fully qualified name with no
    /// Scala declaration (a Java/Kotlin type the realm proved to exist), or an
    /// exact owner whose own member lookup found nothing. Sinks serving foreign
    /// targets match it; every other sink keeps its default no-op (#1859).
    fn record_logical_owner_member(
        &mut self,
        owner_fqn: &str,
        member: &str,
        role: ScalaReferenceRole,
        receiver: ScalaLogicalReceiver,
        call_shape: Option<&ScalaCallSiteShape>,
        node: Node<'_>,
    ) {
        self.sink.record_logical_owner_member(
            ScalaLogicalOwnerMember {
                owner_fqn,
                member,
                role,
                receiver,
                call_shape,
            },
            classify_reference_node(node),
            UsageHitKind::Reference,
            node.start_byte(),
            node.end_byte(),
        );
    }

    /// The candidate fqn when the realm — every language's definition shard,
    /// not only Scala's — proves it names a class-like declaration. `None`
    /// when this scan has no realm view (the edge build) or the realm knows no
    /// such type. A name the Scala index itself holds is never foreign: when
    /// the physical tiers decline to resolve it (replicas, wildcard companion
    /// collisions, package/singleton same-tier clashes), that refusal is the
    /// answer and no lower tier may overrule it (#1859).
    fn realm_class_fqn(&self, candidate: &str) -> Option<String> {
        let workspace = self.workspace?;
        if !self.types.index.by_fqn(candidate).is_empty() {
            return None;
        }
        let normalized = scala_normalized_fq_name(candidate);
        workspace
            .definitions_by_normalized_fqn(&normalized)
            .iter()
            .any(CodeUnit::is_class)
            .then_some(candidate.to_string())
    }

    /// Resolve a written dotted path to the unique foreign (non-Scala) type fqn
    /// it can denote: the path as spelled, its head expanded through this
    /// file's logical import bindings (explicit imports and renames, and
    /// wildcard owners with no Scala backing), or the path under a package
    /// clause in scope — each checked against the realm. `None` when no
    /// candidate exists in the realm or more than one does. This is the
    /// structured counterpart of the retired duplicate scanner's
    /// `QualifierBindings::denoted_paths` (#1859).
    fn realm_foreign_type_fqn(&self, segments: &[String], byte: usize) -> Option<String> {
        self.workspace?;
        let (head, rest) = segments.split_first()?;
        let mut candidates = Vec::new();
        let written = segments.join(".");
        candidates.push(written.clone());
        for base in self.resolver.logical_type_import_candidates(head) {
            let mut expanded = base;
            for segment in rest {
                expanded.push('.');
                expanded.push_str(segment);
            }
            candidates.push(expanded);
        }
        // Wildcard owners with Scala backing never land in the resolver's
        // logical wildcard set (it exists for owners the Scala index lacks),
        // but a wildcard may still bring in a *foreign* type the Scala index
        // does not hold: `import com.example._` with Scala classes in
        // `com.example` still names Java's `com.example.Target` (#1859).
        let package_prefixes = self.package_contexts.prefixes_at(byte);
        for import in self.imports {
            if !import.is_wildcard {
                continue;
            }
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            let lexical_prefixes = import
                .path
                .as_ref()
                .map(|path| path.lexical_prefixes.as_slice())
                .unwrap_or_default();
            for base in scala_import_path_candidates(&path, lexical_prefixes) {
                candidates.push(format!("{base}.{written}"));
            }
        }
        for prefix in package_prefixes {
            if prefix.is_empty() {
                continue;
            }
            candidates.push(format!("{prefix}.{written}"));
        }
        candidates.sort();
        candidates.dedup();
        let mut proven = candidates
            .iter()
            .filter_map(|candidate| self.realm_class_fqn(candidate));
        let resolved = proven.next()?;
        // Two live candidates mean the spelling is ambiguous; fail closed
        // rather than attribute the receiver to one of them.
        proven.next().is_none().then_some(resolved)
    }

    fn record_exact_callable(&mut self, callee: CodeUnit, node: Node<'_>) {
        let Some(call_shape) = call_site_shape_for_reference(node) else {
            self.record_exact(callee, ScalaReferenceRole::Callable, node);
            return;
        };
        self.record_exact_callable_with_shape(callee, node, &call_shape);
    }

    fn record_exact_companion_callable(
        &mut self,
        callee: CodeUnit,
        role: ScalaReferenceRole,
        node: Node<'_>,
    ) {
        debug_assert!(matches!(
            role,
            ScalaReferenceRole::CompanionApplication
                | ScalaReferenceRole::CompanionExtractor
                | ScalaReferenceRole::CompanionValue
        ));
        self.register_invocation_callable(&callee, node);
        // An extractor pattern is a reference to the extractor owner, not a
        // call of the entry point that implements it: `case Foo(a, b)` writes
        // the *result* `unapply` yields, while `unapply` itself takes the one
        // scrutinee. Carrying the pattern's argument list as an ordinary call
        // shape would let it be matched against the entry point's parameter
        // list, which no explicit `unapply` can satisfy. The recorded identity
        // is the entry point; the shape belongs to the owner, so the site is
        // recorded without one (#2078).
        let call_shape = (role != ScalaReferenceRole::CompanionExtractor)
            .then(|| call_site_shape_for_reference(node))
            .flatten();
        let Some(call_shape) = call_shape else {
            self.record_exact(callee, role, node);
            return;
        };
        self.sink.record_callable(
            ScalaResolvedReference::Exact(callee),
            role,
            &call_shape,
            classify_reference_node(node),
            UsageHitKind::Reference,
            node.start_byte(),
            node.end_byte(),
        );
    }

    fn record_exact_callable_with_shape(
        &mut self,
        callee: CodeUnit,
        node: Node<'_>,
        call_shape: &ScalaCallSiteShape,
    ) {
        self.register_invocation_callable(&callee, node);
        let hit_kind = if call_shape.method_value_arity.is_some()
            && !call_shape
                .method_value_parameter_types
                .as_ref()
                .is_some_and(|types| {
                    types.iter().any(|identity| {
                        matches!(identity, ScalaParameterTypeIdentity::Unresolved(_))
                    })
                }) {
            UsageHitKind::Reference
        } else {
            self.callable_reference_hit_kind(node, &callee)
        };
        self.sink.record_callable(
            ScalaResolvedReference::Exact(callee),
            ScalaReferenceRole::Callable,
            call_shape,
            classify_reference_node(node),
            hit_kind,
            node.start_byte(),
            node.end_byte(),
        );
    }

    fn record_resolved(
        &mut self,
        callee: ScalaResolvedReference,
        role: ScalaReferenceRole,
        node: Node<'_>,
    ) {
        self.sink.record(
            callee,
            role,
            classify_reference_node(node),
            UsageHitKind::Reference,
            node.start_byte(),
            node.end_byte(),
        );
    }

    fn record_logical(&mut self, callee: String, role: ScalaReferenceRole, node: Node<'_>) {
        self.sink.record(
            ScalaResolvedReference::Logical(callee),
            role,
            classify_reference_node(node),
            UsageHitKind::Reference,
            node.start_byte(),
            node.end_byte(),
        );
    }

    fn record_unproven_name(&mut self, name: &str, node: Node<'_>) {
        self.sink
            .record_unproven_name(name, node.start_byte(), node.end_byte());
    }
}

fn scala_import_owner_scopes(
    imports: &[ImportInfo],
    class_ranges: &ClassRangeIndex,
    scala: &dyn ScalaSource,
    types: &ProjectTypes,
) -> HashMap<usize, Vec<String>> {
    let mut scopes = HashMap::default();
    for import in imports {
        let Some(path) = import.path.as_ref() else {
            continue;
        };
        let mut owners = Vec::new();
        let mut current = class_ranges
            .enclosing_unit(path.declaration_start_byte)
            .cloned();
        let mut seen = HashSet::default();
        while let Some(owner) = current {
            if !seen.insert(owner.clone()) {
                break;
            }
            current = types.exact_structural_parent(scala, &owner);
            if owner.is_class() {
                owners.push(owner.fq_name());
            }
        }
        scopes.insert(path.declaration_start_byte, owners);
    }
    scopes
}

const SCOPE_NODES: &[&str] = &[
    "class_definition",
    "object_definition",
    "trait_definition",
    "enum_definition",
    "extension_definition",
    "function_definition",
    "block",
    "block_expression",
    "indented_block",
    "case_clause",
    "lambda_expression",
    "anonymous_function",
];

fn walk(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    enum WalkEvent<'tree> {
        Enter(Node<'tree>),
        ActivateCaseBinders(Node<'tree>),
        RefreshAssignment(Node<'tree>),
        ExitScope,
    }

    let mut stack = vec![WalkEvent::Enter(node)];
    while let Some(event) = stack.pop() {
        if ctx.sink.should_stop()
            || ctx
                .cancellation
                .is_some_and(brokk_bifrost_core::cancellation::CancellationToken::is_cancelled)
        {
            break;
        }
        match event {
            WalkEvent::Enter(node) => {
                let enters_scope = walk_enter(node, token, ctx, bindings);
                if enters_scope {
                    stack.push(WalkEvent::ExitScope);
                }
                if node.kind() == "assignment_expression"
                    && !is_scala_named_argument_assignment(node)
                {
                    stack.push(WalkEvent::RefreshAssignment(node));
                }
                let case_pattern = (node.kind() == "case_clause")
                    .then(|| node.child_by_field_name("pattern"))
                    .flatten();
                let mut cursor = node.walk();
                let children = node.named_children(&mut cursor).collect::<Vec<_>>();
                for child in children.into_iter().rev() {
                    if case_pattern == Some(child) {
                        stack.push(WalkEvent::ActivateCaseBinders(child));
                    }
                    stack.push(WalkEvent::Enter(child));
                }
            }
            WalkEvent::ActivateCaseBinders(pattern) => {
                for name in scala_pattern_binder_names(pattern, ctx.source) {
                    bindings.declare_shadow(name.to_string());
                }
            }
            WalkEvent::RefreshAssignment(assignment) => {
                refresh_assignment_binding(assignment, token, ctx, bindings);
            }
            WalkEvent::ExitScope => bindings.exit_scope(),
        }
    }
}

fn walk_enter(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) -> bool {
    ctx.activate_import_context(token, node);
    seed_parent_scope_declaration(node, ctx, bindings);
    let enters_scope = SCOPE_NODES.contains(&node.kind());
    if enters_scope {
        bindings.enter_scope();
    }
    seed_declaration(node, token, ctx, bindings);
    if node.kind() == "import_declaration" {
        record_import_declaration(node, ctx);
    }
    record_override_declaration(node, ctx);
    record_reference(node, token, ctx, bindings);
    enters_scope
}

fn seed_parent_scope_declaration(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    if node.kind() != "function_definition" || !scala_function_definition_is_local(node) {
        return;
    }
    if let Some(name) = node.child_by_field_name("name") {
        let name = node_text(name, ctx.source).trim();
        if !name.is_empty() {
            bindings.declare_shadow(name.to_string());
        }
    }
}

/// Whether `definition` is a *local* `def` -- one a method body declares -- as
/// opposed to a member some template declares.
///
/// The distinction is the nearest enclosing owner, not the presence of a
/// `function_definition` anywhere above (#2079). A `def` inside an anonymous
/// template that a method body constructs (`def m = new T { def helper = .. }`)
/// is a member of that template: extraction mints it as
/// `Owner.m$anon$L:C.helper`, and every bare `helper(..)` inside the template
/// names that member. Reading it as a local `def` of `m` instead declared the
/// name as an opaque shadow across the whole method, which made the inverse
/// scan drop every such call before any owner lookup ran while forward
/// resolution still answered with the minted identity.
///
/// A genuinely nested `def` -- one whose nearest owner really is a method body,
/// including through a block, a lambda, or a `case` clause -- still shadows.
///
/// A `def` inside a template-level `val` initializer reaches a template body
/// first and is therefore not a shadow. That is the answer this rule gave
/// before as well, since no `function_definition` encloses it either.
fn scala_function_definition_is_local(definition: Node<'_>) -> bool {
    let mut current = definition.parent();
    while let Some(ancestor) = current {
        match ancestor.kind() {
            "function_definition" => return true,
            "template_body"
            | "enum_body"
            | "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition"
            | "instance_expression"
            | "extension_definition" => return false,
            _ => {}
        }
        current = ancestor.parent();
    }
    false
}

fn record_import_declaration(node: Node<'_>, ctx: &mut ScalaScan<'_, '_>) {
    let imports = scala_import_infos_from_node(node, ctx.source);
    record_exact_import_references(node, ctx);
    if imports.is_empty() {
        return;
    }
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if is_identifier_node(current) {
            let name = node_text(current, ctx.source).trim();
            if !name.is_empty() {
                ctx.sink.record_import_name(
                    &imports,
                    &ctx.active_package,
                    name,
                    current.start_byte(),
                    current.end_byte(),
                );
            }
        }
        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                stack.push(child);
            }
        }
    }
}

fn record_exact_import_references(node: Node<'_>, ctx: &mut ScalaScan<'_, '_>) {
    let mut path_cursor = node.walk();
    let path_nodes = node
        .children_by_field_name("path", &mut path_cursor)
        .filter(Node::is_named)
        .collect::<Vec<_>>();
    if path_nodes.is_empty() {
        return;
    }
    let base_path = path_nodes
        .iter()
        .map(|segment| node_text(*segment, ctx.source).trim().to_string())
        .collect::<Vec<_>>();
    if base_path.iter().any(|segment| segment.is_empty()) {
        return;
    }
    for end in 1..path_nodes.len() {
        record_exact_import_path_reference(
            path_nodes[end - 1],
            &base_path[..end],
            node.start_byte(),
            true,
            ctx,
        );
    }

    let mut cursor = node.walk();
    let direct_children = node.named_children(&mut cursor).collect::<Vec<_>>();
    if let Some(selectors) = direct_children
        .iter()
        .find(|child| child.kind() == "namespace_selectors")
    {
        if let Some(name_node) = path_nodes.last().copied() {
            record_exact_import_path_reference(
                name_node,
                &base_path,
                node.start_byte(),
                false,
                ctx,
            );
        }
        let mut selector_cursor = selectors.walk();
        let base_name_node = path_nodes.last().copied();
        for selector in selectors.named_children(&mut selector_cursor) {
            record_exact_import_selector_reference(
                selector,
                base_name_node,
                &base_path,
                node.start_byte(),
                ctx,
            );
        }
        return;
    }

    if let Some(selector) = direct_children.iter().find(|child| {
        matches!(
            child.kind(),
            "namespace_wildcard" | "as_renamed_identifier" | "arrow_renamed_identifier"
        )
    }) {
        if let Some(name_node) = path_nodes.last().copied() {
            record_exact_import_path_reference(
                name_node,
                &base_path,
                node.start_byte(),
                false,
                ctx,
            );
        }
        record_exact_import_selector_reference(
            *selector,
            path_nodes.last().copied(),
            &base_path,
            node.start_byte(),
            ctx,
        );
        return;
    }

    if let Some(name_node) = path_nodes.last().copied() {
        record_exact_import_path_reference(name_node, &base_path, node.start_byte(), true, ctx);
    }
}

fn record_exact_import_selector_reference(
    selector: Node<'_>,
    base_name_node: Option<Node<'_>>,
    base_path: &[String],
    declaration_start_byte: usize,
    ctx: &mut ScalaScan<'_, '_>,
) {
    match selector.kind() {
        "namespace_wildcard" => {
            let Some(name_node) = base_name_node else {
                return;
            };
            record_exact_import_path_reference(
                name_node,
                base_path,
                declaration_start_byte,
                false,
                ctx,
            );
        }
        "identifier" | "operator_identifier" | "type_identifier" => {
            let mut path = base_path.to_vec();
            path.push(node_text(selector, ctx.source).trim().to_string());
            record_exact_import_path_reference(selector, &path, declaration_start_byte, true, ctx);
        }
        "as_renamed_identifier" | "arrow_renamed_identifier" => {
            let Some(name_node) = selector.child_by_field_name("name") else {
                return;
            };
            let name = node_text(name_node, ctx.source).trim();
            if name.is_empty() {
                return;
            }
            let mut path = base_path.to_vec();
            path.push(name.to_string());
            record_exact_import_path_reference(name_node, &path, declaration_start_byte, true, ctx);
        }
        _ => {}
    }
}

fn record_exact_import_path_reference(
    name_node: Node<'_>,
    path_segments: &[String],
    declaration_start_byte: usize,
    include_type_targets: bool,
    ctx: &mut ScalaScan<'_, '_>,
) {
    let Some(terminal) = path_segments.last() else {
        return;
    };
    if !ctx.sink.may_match_import_terminal(terminal) {
        return;
    }
    let targets = resolve_exact_import_path_references(
        path_segments,
        declaration_start_byte,
        include_type_targets,
        ctx,
    );
    if targets.is_empty() {
        // A physically unresolved import path may still name a foreign
        // (Java/Kotlin) type: importing `com.example.RetryConfig.withDefaults`
        // references the owner `com.example.RetryConfig` on the way (#1859).
        // The retired duplicate scanner recorded import sites as ordinary
        // references (the external usage surface excludes `Import`-kind hits),
        // so the logical event deliberately keeps `UsageHitKind::Reference`.
        if include_type_targets
            && let Some(foreign) = ctx.realm_foreign_type_fqn(path_segments, declaration_start_byte)
        {
            ctx.record_logical(foreign, ScalaReferenceRole::Type, name_node);
        }
        return;
    }
    for target in targets {
        if target.is_class() && !target.short_name().ends_with('$') {
            ctx.record_exact_import(target.clone(), ScalaReferenceRole::Type, name_node);
            if ctx.types.type_accepts_object_roles(ctx.scala, &target) {
                ctx.record_exact_import(target, ScalaReferenceRole::StableObject, name_node);
            }
            continue;
        }
        let role = if target.is_function() {
            ScalaReferenceRole::Callable
        } else if ctx.types.has_term_field_declaration(&target) {
            ScalaReferenceRole::Field
        } else if target.is_class() && target.short_name().ends_with('$') {
            ScalaReferenceRole::StableObject
        } else {
            ScalaReferenceRole::Type
        };
        ctx.record_exact_import(target, role, name_node);
    }
}

fn resolve_exact_import_path_references(
    path_segments: &[String],
    declaration_start_byte: usize,
    include_type_targets: bool,
    ctx: &ScalaScan<'_, '_>,
) -> Vec<CodeUnit> {
    if path_segments.is_empty() {
        return Vec::new();
    }
    let mut candidates = Vec::new();
    let mut seen = HashSet::default();
    if let Some(owners) = ctx.import_owner_scopes.get(&declaration_start_byte) {
        for owner in owners {
            for candidate in scala_nested_type_candidates(
                owner.trim_end_matches('$').to_string(),
                path_segments,
                true,
            ) {
                if seen.insert(candidate.clone()) {
                    candidates.push(candidate);
                }
            }
        }
    }
    let mut root_is_authoritative = false;
    if let Some((root, tail)) = path_segments.split_first() {
        let lexical_root = ctx.lexically_visible_object_unit(declaration_start_byte, root);
        let owners = if let Some(lexical_root) = &lexical_root {
            vec![lexical_root.clone()]
        } else {
            // A cross-built root is one logical owner with several physical
            // homes (#2021), so every family member contributes its nested
            // type candidates.
            ctx.resolver
                .resolve_units(root)
                .into_iter()
                .chain(ctx.resolver.resolve_object_unit(root))
                .collect()
        };
        root_is_authoritative = !owners.is_empty();
        if root_is_authoritative {
            candidates.clear();
            seen.clear();
        }
        for owner in owners {
            for candidate in scala_nested_type_candidates(
                owner.fq_name().trim_end_matches('$').to_string(),
                tail,
                true,
            ) {
                if seen.insert(candidate.clone()) {
                    candidates.push(candidate);
                }
            }
        }
    }
    if !root_is_authoritative {
        let relative_path = path_segments.join(".");
        let package_prefixes = ctx
            .active_resolver_key
            .as_ref()
            .map(|(packages, _)| packages.clone())
            .filter(|packages| !packages.is_empty())
            .unwrap_or_else(|| {
                if ctx.active_package.is_empty() {
                    Vec::new()
                } else {
                    vec![ctx.active_package.clone()]
                }
            });
        for candidate in scala_import_path_candidates(&relative_path, &package_prefixes) {
            if seen.insert(candidate.clone()) {
                candidates.push(candidate);
            }
        }
    }
    let mut field_targets = HashSet::default();
    let mut callable_targets = HashSet::default();
    let mut object_targets = HashSet::default();
    let mut type_targets = HashSet::default();
    for candidate in candidates {
        let categorized = exact_import_targets_for_candidate(&candidate, ctx);
        field_targets.extend(categorized.field_targets);
        callable_targets.extend(categorized.callable_targets);
        object_targets.extend(categorized.object_targets);
        if include_type_targets {
            type_targets.extend(categorized.type_targets);
        }
    }

    for object in &object_targets {
        type_targets.remove(object);
    }

    let mut exact = Vec::new();
    for targets in [
        field_targets,
        callable_targets,
        object_targets,
        type_targets,
    ] {
        // One selectable declaration per role; a same-file overload family
        // counts as one declaration and contributes every overload unit
        // (#1327), and a coherent replica family counts as one declaration and
        // contributes every physical member (#2021).
        let targets = sorted_unique_units(targets.into_iter().collect());
        if !targets.is_empty() && single_replica_family(targets.iter()) {
            exact.extend(targets);
        }
    }
    exact
}

#[derive(Default)]
struct ExactImportTargets {
    field_targets: HashSet<CodeUnit>,
    callable_targets: HashSet<CodeUnit>,
    object_targets: HashSet<CodeUnit>,
    type_targets: HashSet<CodeUnit>,
}

fn exact_import_targets_for_candidate(
    candidate: &str,
    ctx: &ScalaScan<'_, '_>,
) -> ExactImportTargets {
    let normalized = scala_normalized_fq_name(candidate);
    let mut exact = ExactImportTargets::default();
    for member in ctx.types.importable_members_by_normalized_fqn(
        ctx.scala,
        &normalized,
        Some(ctx.source_file),
    ) {
        if member.is_function() {
            exact.callable_targets.insert(member.clone());
        } else if ctx.types.has_term_field_declaration(&member) {
            exact.field_targets.insert(member.clone());
        }
    }

    if let Some(object) = ctx.types.object_by_normalized_fqn(ctx.scala, &normalized) {
        exact.object_targets.insert(object.clone());
    }
    let (type_declarations, object_declarations) =
        ctx.types.explicit_import_type_declarations(candidate);
    for declaration in object_declarations {
        exact.object_targets.insert(declaration);
    }
    for declaration in type_declarations {
        if ctx.types.type_accepts_object_roles(ctx.scala, &declaration) {
            let companions = ctx.types.exact_companion_objects(ctx.scala, &declaration);
            if !companions.is_empty() {
                exact.object_targets.extend(companions);
            } else {
                exact.object_targets.insert(declaration.clone());
            }
        }
        if !exact.object_targets.contains(&declaration) {
            exact.type_targets.insert(declaration);
        }
    }
    exact
}

/// The receiver value node of a `recv.method` call when `node` is the `field`
/// child of a `field_expression`; `None` for a bare `method()` call (no explicit
/// receiver). Used by the same-owner classification to inspect the receiver
/// shape (`this` / `super` / a named own-object) at the record site.
fn callable_receiver_value(node: Node<'_>) -> Option<Node<'_>> {
    let parent = node.parent()?;
    (parent.kind() == "field_expression" && parent.child_by_field_name("field") == Some(node))
        .then(|| parent.child_by_field_name("value"))
        .flatten()
}

/// Whether the callable reference `node` is an actual invocation — a bare call
/// `m(..)`, or the `field` of a `recv.m(..)` whose `field_expression` is the
/// function of a call. A reference in argument/value position (a method value)
/// is not an invocation, so it is never a self-receiver *call*.
fn scala_reference_is_invoked(node: Node<'_>) -> bool {
    if is_call_function_reference(node) {
        return true;
    }
    node.parent().is_some_and(|parent| {
        parent.kind() == "field_expression"
            && parent.child_by_field_name("field") == Some(node)
            && is_call_function_reference(parent)
    })
}

/// The term field named `member` that the template chain enclosing `byte`
/// declares or inherits, innermost template first.
fn scala_enclosing_chain_field(
    ctx: &ScalaScan<'_, '_>,
    token: QueryToken<'_>,
    byte: usize,
    member: &str,
) -> Option<CodeUnit> {
    let mut enclosing = ctx.enclosing_class_unit(byte).cloned();
    while let Some(owner) = enclosing {
        if let FieldResolution::Resolved(field) = ctx
            .types
            .field_for_owner_unit(ctx.scala, token, &owner, member)
        {
            return Some(field.declaration);
        }
        enclosing = ctx.scala.structural_parent_of(&owner);
    }
    None
}

fn record_reference(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) {
    if node.kind() == "type_identifier"
        && !is_extractor_reference(node)
        && !is_infix_pattern_operator(node)
    {
        let lookup = scala_qualified_type_root(node);
        let segments = scala_type_lookup_segments(lookup, ctx.source);
        if !segments
            .iter()
            .any(|segment| ctx.sink.may_match_name(segment))
        {
            return;
        }
    }
    let named_argument_label =
        node.kind() == "identifier" && named_argument_invocation_owner(node).is_some();
    if let Some(name) = reference_lookup_name(node, ctx.source)
        && !named_argument_label
        && !ctx.sink.may_match_name(name)
    {
        return;
    }
    match node.kind() {
        // A type reference in any type position: param/return types, `extends`,
        // and the type child of `new Foo()`. Construction is covered here without
        // a separate `instance_expression` case (avoids double counting).
        "type_identifier" => {
            let text = node_text(node, ctx.source);
            if node
                .parent()
                .filter(|parent| parent.kind() == "projected_type")
                .is_some_and(|projection| projection.child_by_field_name("selector") == Some(node))
            {
                // `Owner#Member` names a type member of the type on the left of
                // `#`, so this shape owns the name either way: falling through
                // would look the member up as a bare type name and attribute it
                // to an unrelated top-level declaration of the same spelling.
                if let Some(target) = projected_type_member_declaration(node, token, ctx) {
                    ctx.record_exact(target, ScalaReferenceRole::Type, node);
                }
                return;
            }
            if record_qualified_root_owner_reference(node, token, text, ctx, bindings) {
                return;
            }
            if record_intermediate_stable_object_reference(node, ctx, bindings) {
                return;
            }
            if record_qualified_stable_reference(node, token, ctx, bindings) {
                return;
            }
            if is_stable_type_qualifier(node)
                && bindings.resolve_symbol(text).is_unknown()
                && !bindings.is_shadowed(text)
                && let Some(ScalaResolvedReference::Exact(target)) =
                    ctx.visible_type_reference(token, node, text)
                && target.is_class()
                && !target.short_name().ends_with('$')
                && ctx.types.type_is_stable_owner(ctx.scala, &target)
            {
                ctx.record_exact(target, ScalaReferenceRole::Type, node);
                return;
            }
            let object_reference = is_scala_object_reference(node);
            // A template's own `val` is seeded into the local engine so that
            // `Tag.toString` can dispatch on it. In pattern position that
            // binding is not a shadow of the extractor: it *is* the extractor
            // the pattern names, which is why `private val Rgx = "...".r` in
            // an enclosing object matched nothing here. Forward lookup answers
            // the same enclosing chain, so record the same field.
            if (is_extractor_reference(node) || is_infix_pattern_operator(node))
                && precise_scala_binding(bindings, text)
                    .is_some_and(|binding| binding.declaration_owner.is_some())
                && let Some(field) =
                    scala_enclosing_chain_field(ctx, token, node.start_byte(), text)
            {
                ctx.record_exact(field, ScalaReferenceRole::Field, node);
                return;
            }
            if (is_extractor_reference(node) || is_infix_pattern_operator(node))
                && bindings.resolve_symbol(text).is_unknown()
                && !bindings.is_shadowed(text)
            {
                // Extractors live in Scala's term namespace. An inherited
                // stable field therefore wins even when a same-named type
                // alias is visible (for example `FSM.Event`, where the trait
                // exposes both `type Event` and `val Event`). Resolve that
                // exact field before consulting type/application candidates.
                //
                // The whole lexically enclosing chain is consulted, innermost
                // first, not only the innermost template: lagom declares
                // `private val JavaHomeDir = "...".r` on an object and matches
                // against it from nested classes of that object. Forward
                // lookup answers the same chain in the same order, so both
                // ends agree on which template's value a nested class sees.
                if let Some(field) =
                    scala_enclosing_chain_field(ctx, token, node.start_byte(), text)
                {
                    ctx.record_exact(field, ScalaReferenceRole::Field, node);
                    return;
                }
                let class_fqn = ctx.visible_type(token, node, text);
                let resolution = ctx.types.resolve_type_application(
                    ctx.scala,
                    token,
                    &ctx.resolver,
                    class_fqn.as_deref(),
                    ctx.lexically_visible_object(node.start_byte(), text)
                        .or_else(|| ctx.resolver.resolve_object(text))
                        .as_deref(),
                    text,
                    call_site_shape_for_reference(node).as_ref(),
                    TypeApplicationRole::Extractor,
                    Some(ctx.source_file),
                );
                let resolved =
                    resolution.type_target.is_some() || !resolution.callable_targets.is_empty();
                if let Some(target) = resolution.type_target {
                    ctx.record_exact(target, ScalaReferenceRole::Type, node);
                }
                for callable in resolution.callable_targets {
                    ctx.record_exact_companion_callable(
                        callable,
                        ScalaReferenceRole::CompanionExtractor,
                        node,
                    );
                }
                if resolved {
                    return;
                }
            }
            let resolved = if object_reference {
                (bindings.resolve_symbol(text).is_unknown() && !bindings.is_shadowed(text))
                    .then(|| ctx.visible_object_reference(node.start_byte(), text))
                    .flatten()
            } else if is_scala_class_reference(node, ctx.source) {
                ctx.visible_type_reference(token, node, text)
            } else {
                None
            };
            // A type the Scala index does not hold gets one structured chance
            // through the realm before the reference goes unrecorded (#1859).
            if resolved.is_none() {
                record_foreign_type_reference(node, token, text, ctx, bindings);
                return;
            }
            if let Some(resolved) = resolved {
                if is_constructor_like_reference(node, ctx.source) {
                    if let ScalaResolvedReference::Exact(alias) = &resolved
                        && ctx.types.is_type_alias(ctx.scala, alias)
                    {
                        ctx.record_exact(alias.clone(), ScalaReferenceRole::Type, node);
                        return;
                    }
                    let fqn = match &resolved {
                        ScalaResolvedReference::Exact(unit) => unit.fq_name(),
                        ScalaResolvedReference::Logical(fqn) => fqn.clone(),
                    };
                    let resolution = ctx.types.resolve_type_application(
                        ctx.scala,
                        token,
                        &ctx.resolver,
                        Some(&fqn),
                        None,
                        text,
                        call_site_shape_for_reference(node).as_ref(),
                        TypeApplicationRole::ExplicitConstructor,
                        Some(ctx.source_file),
                    );
                    if let Some(target) = resolution.type_target {
                        ctx.record_exact(target, ScalaReferenceRole::Type, node);
                    }
                    for callable in resolution.callable_targets {
                        ctx.record_exact_callable(callable, node);
                    }
                    return;
                }
                ctx.record_resolved(
                    resolved,
                    if object_reference {
                        ScalaReferenceRole::StableObject
                    } else {
                        ScalaReferenceRole::Type
                    },
                    node,
                );
            }
        }
        "call_expression" => {
            let Some(function) = node.child_by_field_name("function") else {
                return;
            };
            let function = invocation_function_reference(function);
            match function.kind() {
                // `recv.method(..)` — type the receiver, then `Owner.method`.
                "field_expression" => {
                    let (Some(receiver), Some(field)) = (
                        function.child_by_field_name("value"),
                        function.child_by_field_name("field"),
                    ) else {
                        return;
                    };
                    let name = node_text(field, ctx.source);
                    if name.is_empty() {
                        return;
                    }
                    // `super.m(..)` is an up-call: the parent linearization
                    // answers it, and no other receiver rule may reinterpret
                    // the selection when it does not.
                    if node_text(receiver, ctx.source).trim() == "super" {
                        record_super_member(field, token, name, ctx);
                        return;
                    }
                    // `C.apply(..)` on a case class selects the synthetic apply
                    // its companion carries, which is the primary constructor.
                    // Ordinary member lookup cannot reach it: the companion
                    // declares no `apply` of its own, and an `apply` it inherits
                    // is not the callee.
                    if name == "apply"
                        && record_explicit_case_class_apply(receiver, token, field, ctx, bindings)
                    {
                        return;
                    }
                    if name == "copy" && record_case_class_copy(receiver, token, ctx, bindings) {
                        return;
                    }
                    // A parser-proven stable application such as
                    // `Uri.UserInfo(...)` names a type/companion application,
                    // even when `Uri` is also a resolvable stable receiver.
                    // Resolve that namespace form before ordinary receiver
                    // method lookup can consume the terminal as a member.
                    if qualified_stable_type_reference(field, ctx.source).is_some()
                        && record_qualified_stable_reference(field, token, ctx, bindings)
                    {
                        return;
                    }
                    if receiver.kind() == "identifier"
                        && let Some(receiver_bindings) = bindings
                            .resolve_symbol_ref(node_text(receiver, ctx.source))
                            .and_then(|resolution| resolution.as_precise())
                        && receiver_bindings.len() > 1
                    {
                        let Some(call_shape) = call_site_shape_for_reference(field) else {
                            return;
                        };
                        let mut methods = Vec::new();
                        for binding in receiver_bindings {
                            let Some(owner) = binding.receiver_type.as_deref() else {
                                return;
                            };
                            let BareMemberResolution::Resolved(resolved) = ctx
                                .types
                                .effective_method_declarations_for_owner_with_shape(
                                    ctx.scala,
                                    token,
                                    owner,
                                    name,
                                    &call_shape,
                                )
                            else {
                                return;
                            };
                            if resolved.is_empty() {
                                return;
                            }
                            methods.extend(resolved);
                        }
                        methods.sort();
                        methods.dedup();
                        for method in methods {
                            ctx.record_exact_callable_with_shape(method, field, &call_shape);
                        }
                        return;
                    }
                    if let Some(owner) = receiver_value_owner(receiver, token, ctx, bindings) {
                        let Some(call_shape) = call_site_shape_for_reference(field) else {
                            return;
                        };
                        let owner_fqn = match &owner {
                            ScalaValueOwner::Exact(owner) => owner.fq_name(),
                            ScalaValueOwner::Logical(owner) => owner.clone(),
                        };
                        let field_resolution = match &owner {
                            ScalaValueOwner::Exact(owner) => ctx
                                .types
                                .field_for_owner_unit(ctx.scala, token, owner, name),
                            ScalaValueOwner::Logical(owner) => ctx
                                .types
                                .field_for_owner_member(ctx.scala, token, owner, name),
                        };
                        match field_resolution {
                            FieldResolution::Resolved(resolved) => {
                                // A selected value remains a reference to that exact field even
                                // when Scala immediately applies/indexes the returned value. The
                                // terminal `call_expression` owns this event because its child is
                                // deliberately suppressed below to preserve shaped-call safety.
                                ctx.record_exact(
                                    resolved.declaration,
                                    ScalaReferenceRole::Field,
                                    field,
                                );
                                return;
                            }
                            FieldResolution::Unresolved => return,
                            FieldResolution::NoMatch => {}
                        }
                        let method_value_shape =
                            match companion_method_value_context(node, token, ctx, bindings) {
                                ScalaMethodValueContext::Function(shape) => Some(shape),
                                ScalaMethodValueContext::Unknown
                                | ScalaMethodValueContext::Incompatible => None,
                            };
                        let call_shape = call_shape.with_method_value_shape(method_value_shape);
                        let call_arities = call_shape
                            .lists
                            .iter()
                            .map(|list| list.arity)
                            .collect::<Vec<_>>();
                        let resolution = match &owner {
                            ScalaValueOwner::Exact(owner) => ctx
                                .types
                                .effective_method_declarations_for_exact_owner_with_shape(
                                    ctx.scala,
                                    token,
                                    owner,
                                    name,
                                    &call_shape,
                                ),
                            ScalaValueOwner::Logical(owner) => ctx
                                .types
                                .effective_method_declarations_for_owner_with_shape(
                                    ctx.scala,
                                    token,
                                    owner,
                                    name,
                                    &call_shape,
                                ),
                        };
                        match resolution {
                            BareMemberResolution::Resolved(methods) => {
                                for method in methods {
                                    ctx.record_exact_callable_with_shape(
                                        method,
                                        field,
                                        &call_shape,
                                    );
                                }
                            }
                            BareMemberResolution::Unresolved => {}
                            BareMemberResolution::NoMatch => {
                                if record_qualified_stable_reference(field, token, ctx, bindings) {
                                    return;
                                }
                                let extensions = visible_extensions(
                                    ctx,
                                    token,
                                    name,
                                    Some(&owner_fqn),
                                    Some(call_arities.as_slice()),
                                );
                                if extensions.is_empty() {
                                    // The receiver type is proven, but no
                                    // Scala declaration of the member exists:
                                    // a foreign (Java/Kotlin) owner-member
                                    // reference (#1859).
                                    ctx.record_logical_owner_member(
                                        &owner_fqn,
                                        name,
                                        ScalaReferenceRole::Callable,
                                        ScalaLogicalReceiver::Instance,
                                        Some(&call_shape),
                                        field,
                                    );
                                }
                                for extension in extensions {
                                    ctx.record_exact(
                                        extension.declaration,
                                        ScalaReferenceRole::Callable,
                                        field,
                                    );
                                }
                            }
                        }
                    } else if !record_qualified_stable_reference(field, token, ctx, bindings)
                        && !record_qualified_package_call(field, token, ctx)
                    {
                        let call_arities = call_arities_for_reference(field);
                        let extensions =
                            visible_extensions(ctx, token, name, None, call_arities.as_deref());
                        if extensions.is_empty() {
                            // A receiver the value bindings cannot type may
                            // still spell a foreign type itself
                            // (`Config.of(..)`); that is a static-style
                            // reference, not an unproven one (#1859).
                            if let Some(static_owner) =
                                realm_static_owner_fqn(receiver, ctx, bindings)
                            {
                                ctx.record_logical_owner_member(
                                    &static_owner,
                                    name,
                                    ScalaReferenceRole::Callable,
                                    ScalaLogicalReceiver::StaticOwner,
                                    call_site_shape_for_reference(field).as_ref(),
                                    field,
                                );
                            } else {
                                ctx.record_unproven_name(name, field);
                            }
                        } else {
                            for extension in extensions {
                                ctx.record_exact(
                                    extension.declaration,
                                    ScalaReferenceRole::Callable,
                                    field,
                                );
                            }
                        }
                    }
                }
                // `method(..)` — unqualified, attributes to the enclosing class.
                "identifier" => {
                    let name = node_text(function, ctx.source);
                    if name.is_empty() {
                        return;
                    }
                    let Some(call_shape) = call_site_shape_for_reference(function) else {
                        return;
                    };
                    let method_value_shape =
                        match companion_method_value_context(node, token, ctx, bindings) {
                            ScalaMethodValueContext::Function(shape) => Some(shape),
                            ScalaMethodValueContext::Unknown
                            | ScalaMethodValueContext::Incompatible => None,
                        };
                    let call_shape = call_shape.with_method_value_shape(method_value_shape);
                    let lexical_callable_bound = match record_unqualified_applied_field(
                        function, token, name, ctx, bindings,
                    ) {
                        LexicalFieldReferenceResolution::Consumed => return,
                        LexicalFieldReferenceResolution::CallableBound => true,
                        LexicalFieldReferenceResolution::NoMatch => false,
                    };
                    if !lexical_callable_bound
                        && (!bindings.resolve_symbol(name).is_unknown()
                            || bindings.is_shadowed(name))
                    {
                        return;
                    }
                    if record_lexically_visible_call(function, token, name, &call_shape, ctx) {
                        return;
                    }
                    if lexical_callable_bound {
                        return;
                    }
                    let resolved_member_units = ctx.resolver.resolve_member_units(name);
                    let imported_type_alias_only = !resolved_member_units.is_empty()
                        && resolved_member_units
                            .iter()
                            .all(|unit| ctx.types.is_exclusive_type_alias(unit));
                    let imported_units = resolved_member_units
                        .into_iter()
                        .filter(|unit| {
                            unit.is_function() || ctx.types.has_term_field_declaration(unit)
                        })
                        .collect::<Vec<_>>();
                    if !imported_units.is_empty()
                        && imported_units.iter().all(|unit| unit.is_synthetic())
                        && (ctx.visible_type(token, function, name).is_some()
                            || ctx
                                .visible_object_reference(function.start_byte(), name)
                                .is_some())
                    {
                        record_unqualified_type_application(function, token, name, ctx, bindings);
                        return;
                    }
                    if !imported_units.is_empty() {
                        let imported_fields = imported_units
                            .iter()
                            .filter(|unit| ctx.types.has_term_field_declaration(unit))
                            .cloned()
                            .collect::<Vec<_>>();
                        if !imported_fields.is_empty() {
                            if let [field] = imported_fields.as_slice()
                                && (field.source() == ctx.source_file
                                    || ctx.types.term_field_declaration_is_globally_unique(field))
                            {
                                ctx.record_exact(
                                    field.clone(),
                                    ScalaReferenceRole::Field,
                                    function,
                                );
                            }
                            return;
                        }
                        let imported_refs = imported_units.iter().collect::<Vec<_>>();
                        for target in ctx.types.method_declarations_for_members_with_shape(
                            ctx.scala,
                            token,
                            &imported_refs,
                            &call_shape,
                        ) {
                            ctx.record_exact_callable_with_shape(target, function, &call_shape);
                        }
                        return;
                    }
                    if ctx.visible_type(token, function, name).is_some()
                        || ctx
                            .visible_object_reference(function.start_byte(), name)
                            .is_some()
                    {
                        record_unqualified_type_application(function, token, name, ctx, bindings);
                        return;
                    }
                    if !imported_type_alias_only
                        && let Some(imported) = ctx.resolver.resolve_member(name)
                    {
                        for target in ctx.types.imported_member_targets_with_shape(
                            ctx.scala,
                            token,
                            &imported,
                            &call_shape,
                        ) {
                            ctx.record_exact_callable_with_shape(target, function, &call_shape);
                        }
                        // A unique imported binding owns this visible name.
                        // If no overload matches the call shape, fail closed
                        // instead of reinterpreting it as a type application.
                        return;
                    }
                    record_unqualified_type_application(function, token, name, ctx, bindings);
                }
                _ => {}
            }
        }
        "infix_expression" => {
            let (Some(left), Some(operator)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("operator"),
            ) else {
                return;
            };
            let member = node_text(operator, ctx.source).trim();
            if member.is_empty() {
                return;
            }
            // Scala makes an operator right-associative exactly when its last
            // character is `:`, and then the *right* operand is the receiver:
            // `h :: acc` is `acc.::(h)`. Reading the left operand as the
            // receiver leaves every `::`, `+:` and `<:::` call unresolved.
            let receiver = if member.ends_with(':') {
                let Some(right) = node.child_by_field_name("right") else {
                    return;
                };
                right
            } else {
                left
            };
            let Some(owner) = receiver_value_owner(receiver, token, ctx, bindings) else {
                return;
            };
            let call_arities = call_arities_for_reference(operator);
            let resolution = match &owner {
                ScalaValueOwner::Exact(owner) => {
                    ctx.types.effective_method_declarations_for_exact_owner(
                        ctx.scala,
                        token,
                        owner,
                        member,
                        call_arities.as_deref(),
                    )
                }
                ScalaValueOwner::Logical(owner) => {
                    ctx.types.effective_method_declarations_for_owner(
                        ctx.scala,
                        token,
                        owner,
                        member,
                        call_arities.as_deref(),
                    )
                }
            };
            if let BareMemberResolution::Resolved(methods) = resolution {
                for method in methods {
                    ctx.record_exact_callable(method, operator);
                }
            }
        }
        "postfix_expression" => {
            let Some(operator) = scala_postfix_operator_node(node) else {
                return;
            };
            let Some(receiver) = scala_postfix_receiver_node(node, operator) else {
                return;
            };
            let member = node_text(operator, ctx.source).trim();
            if member.is_empty() {
                return;
            }
            let Some(owner) = receiver_value_owner(receiver, token, ctx, bindings) else {
                return;
            };
            let resolution = match &owner {
                ScalaValueOwner::Exact(owner) => {
                    ctx.types.effective_method_declarations_for_exact_owner(
                        ctx.scala, token, owner, member, None,
                    )
                }
                ScalaValueOwner::Logical(owner) => ctx
                    .types
                    .effective_method_declarations_for_owner(ctx.scala, token, owner, member, None),
            };
            if let BareMemberResolution::Resolved(methods) = resolution {
                for method in methods {
                    ctx.record_exact_callable(method, operator);
                }
            }
        }
        "identifier" | "operator_identifier" => {
            let name = node_text(node, ctx.source);
            if name.is_empty() {
                return;
            }
            if has_ancestor_kind(node, "import_declaration") {
                record_local_stable_imported_member(node, token, name, ctx, bindings);
                return;
            }
            if let Some(invocation_function) = named_argument_invocation_owner(node)
                && let Some(owner_node) = terminal_invocation_owner_name(invocation_function)
            {
                let owner_name = node_text(owner_node, ctx.source).trim();
                if owner_name == "copy"
                    && invocation_function.kind() == "field_expression"
                    && let Some(receiver) = invocation_function.child_by_field_name("value")
                    && let Some(owner) = case_class_copy_owner(receiver, token, ctx, bindings)
                {
                    ctx.record_exact_owner_member(owner, name, ScalaReferenceRole::Field, node);
                    return;
                }
                let declaring_callables = named_argument_callable_targets(owner_node, name, ctx);
                if let Some(ScalaResolvedReference::Exact(owner)) =
                    ctx.visible_type_reference(token, owner_node, owner_name)
                {
                    let callable_matches_owner = declaring_callables.iter().any(|callable| {
                        ctx.scala.structural_parent_of(callable).as_ref() == Some(&owner)
                    });
                    let owner_declares_member = !ctx
                        .types
                        .exact_member_declarations(ctx.scala, &owner, name)
                        .is_empty();
                    // A parameter of the owner's own constructor and a member
                    // the owner declares under the same name are one source
                    // entity: a case-class parameter is both. The label names
                    // that entity, so record both identities. A callable owned
                    // by something else -- a companion `apply` next to an
                    // unrelated member of the same name (#1861) -- is not the
                    // owner's member, and only the callable is recorded.
                    if declaring_callables.is_empty()
                        || (callable_matches_owner && owner_declares_member)
                    {
                        ctx.record_exact_owner_member(owner, name, ScalaReferenceRole::Field, node);
                    }
                    for callable in declaring_callables {
                        ctx.record_exact_callable(callable, node);
                    }
                } else {
                    for callable in declaring_callables {
                        ctx.record_exact_callable(callable, node);
                    }
                }
                return;
            }
            if is_declaration_name(node) {
                return;
            }
            // A parameterless `super.m`, the selection form of the up-call the
            // `call_expression` arm resolves.
            if is_super_selection(node, ctx.source) {
                record_super_member(node, token, name, ctx);
                return;
            }
            if record_qualified_root_owner_reference(node, token, name, ctx, bindings) {
                return;
            }
            if record_intermediate_stable_object_reference(node, ctx, bindings) {
                return;
            }
            if qualified_stable_type_reference(node, ctx.source).is_some_and(|reference| {
                reference.role == ScalaQualifiedStableTypeRole::Type
                    && reference.segments.first().is_none_or(|root| {
                        bindings.resolve_symbol(root).is_unknown() && !bindings.is_shadowed(root)
                    })
            }) && record_qualified_stable_reference(node, token, ctx, bindings)
            {
                return;
            }
            if is_scala_case_pattern_binder(node, ctx.source) {
                return;
            }
            // The enclosing `call_expression` owns callable-shape resolution.
            // Visiting its bare function identifier again must not add an
            // unshaped imported-member edge after an arity mismatch.
            if is_call_function_reference(node) || reference_is_owned_by_invocation(node) {
                return;
            }
            if record_local_stable_imported_member(node, token, name, ctx, bindings)
                || record_local_stable_field_reference(node, token, ctx, bindings)
                || record_enclosing_field_qualifier(node, token, name, ctx, bindings)
            {
                return;
            }
            if !is_terminal_stable_field_reference(node) && !is_field_expression_value(node) {
                if record_lexically_visible_field_reference(node, token, name, ctx, bindings)
                    == LexicalFieldReferenceResolution::Consumed
                {
                    return;
                }
                if !matches!(
                    companion_method_value_context(node, token, ctx, bindings),
                    ScalaMethodValueContext::Function(_)
                ) && record_lexically_visible_parameterless_method(node, token, name, ctx)
                {
                    return;
                }
            }
            if !is_terminal_stable_field_reference(node)
                && record_qualified_stable_reference(node, token, ctx, bindings)
            {
                return;
            }
            // `X.this` names the enclosing template `X`, whatever its kind,
            // and so does the qualifier of `private[X]`. A trait is neither a
            // stable owner nor an object, so the rules below cannot reach it
            // (#2082). An access qualifier that names an enclosing package
            // instead resolves to no template and stays unrecorded.
            if let Some(qualifier) = is_enclosing_template_qualifier_reference(node, ctx.source)
                .then(|| ctx.enclosing_template_named(node.start_byte(), name))
                .flatten()
            {
                ctx.record_exact(qualifier, ScalaReferenceRole::Type, node);
                return;
            }
            // A stable selection's root is an independently meaningful term
            // reference. Resolve it before class/type handling consumes the same
            // spelling, so `Flag` in `Flag.values` is attributed to the exact
            // companion object while `Flag` in a type position still resolves to
            // the class/enum namespace below.
            if is_field_expression_value(node)
                && bindings.resolve_symbol(name).is_unknown()
                && !bindings.is_shadowed(name)
            {
                if let Some(ScalaResolvedReference::Exact(target)) =
                    ctx.visible_type_reference(token, node, name)
                    && ctx.types.type_is_stable_owner(ctx.scala, &target)
                {
                    ctx.record_exact(target, ScalaReferenceRole::Type, node);
                    return;
                }
                if let Some(target) = ctx.visible_object_reference(node.start_byte(), name) {
                    ctx.record_resolved(target, ScalaReferenceRole::StableObject, node);
                    return;
                }
            }
            let bare_companion_method_value = is_bare_companion_method_value_reference(node);
            if (is_extractor_reference(node) || is_infix_pattern_operator(node))
                && bindings.resolve_symbol(name).is_unknown()
                && !bindings.is_shadowed(name)
                && names_extractor_owner(node, token, name, ctx)
            {
                record_unqualified_type_application(node, token, name, ctx, bindings);
                return;
            }
            if is_scala_class_reference(node, ctx.source)
                && !bare_companion_method_value
                && let Some(target) = ctx.visible_type_reference(token, node, name)
            {
                ctx.record_resolved(target, ScalaReferenceRole::Type, node);
                return;
            }
            if let ScalaMethodValueContext::Function(shape) =
                companion_method_value_context(node, token, ctx, bindings)
            {
                let call_shape = ScalaCallSiteShape {
                    lists: Vec::new(),
                    leading_literal_argument_types: None,
                    method_value_arity: Some(shape.arity),
                    method_value_parameter_types: shape.parameter_types,
                    method_value_parameter_types_authoritative: shape.parameter_types_authoritative,
                    type_arguments_only: false,
                };
                if record_lexically_visible_call(node, token, name, &call_shape, ctx) {
                    return;
                }
                if let Some(imported) = ctx.resolver.resolve_member(name) {
                    let targets = ctx.types.imported_member_targets_with_shape(
                        ctx.scala,
                        token,
                        &imported,
                        &call_shape,
                    );
                    for target in targets {
                        ctx.record_exact_callable(target, node);
                    }
                    return;
                }
                if !bare_companion_method_value {
                    return;
                }
            }
            if !is_terminal_stable_field_reference(node)
                && record_explicit_imported_member(node, name, ctx)
            {
                return;
            }
            if !is_terminal_stable_field_reference(node)
                && !bare_companion_method_value
                && let Some(imported) = ctx.resolver.resolve_explicit_member_unit(name)
            {
                ctx.record_exact(
                    imported.clone(),
                    if imported.is_field() {
                        ScalaReferenceRole::Field
                    } else {
                        ScalaReferenceRole::Callable
                    },
                    node,
                );
                return;
            }
            if !is_terminal_stable_field_reference(node)
                && ctx
                    .lexically_visible_object(node.start_byte(), name)
                    .is_none()
            {
                for declaration in enclosing_template_declarations(node) {
                    if let Some(owner) = ctx
                        .class_ranges
                        .unit_for_exact_span(declaration.start_byte(), declaration.end_byte())
                        .cloned()
                    {
                        for role in [ScalaReferenceRole::Field, ScalaReferenceRole::Callable] {
                            ctx.record_exact_owner_member(owner.clone(), name, role, node);
                        }
                    }
                }
            }
            if !is_terminal_stable_field_reference(node)
                && let Some(call_shape) = call_site_shape_for_reference(node)
                && call_shape.type_arguments_only
            {
                if record_lexically_visible_call(node, token, name, &call_shape, ctx) {
                    return;
                }
                if let Some(imported) = ctx.resolver.resolve_member(name) {
                    for target in ctx.types.imported_member_targets_with_shape(
                        ctx.scala,
                        token,
                        &imported,
                        &call_shape,
                    ) {
                        ctx.record_exact_callable(target, node);
                    }
                    return;
                }
                record_unqualified_type_application(node, token, name, ctx, bindings);
                return;
            }
            if bare_companion_method_value {
                if let Some(imported) = ctx.resolver.resolve_explicit_member_unit(name) {
                    ctx.record_exact(
                        imported.clone(),
                        if imported.is_field() {
                            ScalaReferenceRole::Field
                        } else {
                            ScalaReferenceRole::Callable
                        },
                        node,
                    );
                    return;
                }
                let target = match companion_method_value_context(node, token, ctx, bindings) {
                    ScalaMethodValueContext::Unknown => {
                        // An explicit companion object is a stable term in an
                        // ordinary value argument.  Do not reinterpret a
                        // case-class companion with an unknown callee shape as
                        // its synthetic `apply` method value: that would record
                        // the class namespace and lose the object reference
                        // (for example `List[Spec](CaseClass)` where the
                        // companion object extends `Spec`).
                        if let Some(ScalaResolvedReference::Exact(object)) =
                            ctx.visible_object_reference(node.start_byte(), name)
                            && object.is_class()
                            && object.short_name().ends_with('$')
                        {
                            ctx.record_exact(object, ScalaReferenceRole::StableObject, node);
                            return;
                        }
                        ctx.types.unique_companion_apply_method_value_target(
                            ctx.scala,
                            token,
                            &ctx.resolver,
                            name,
                            None,
                        )
                    }
                    ScalaMethodValueContext::Function(shape) => {
                        ctx.types.unique_companion_apply_method_value_target(
                            ctx.scala,
                            token,
                            &ctx.resolver,
                            name,
                            Some(&[shape.arity]),
                        )
                    }
                    ScalaMethodValueContext::Incompatible => {
                        if let Some(object) = ctx.resolver.resolve_object_unit(name) {
                            ctx.record_exact(object, ScalaReferenceRole::StableObject, node);
                        } else if let Some(object) = ctx.resolver.resolve_object(name) {
                            ctx.record_logical(object, ScalaReferenceRole::StableObject, node);
                        }
                        None
                    }
                };
                if let Some(target) = target {
                    ctx.record_exact_companion_callable(
                        target,
                        ScalaReferenceRole::CompanionValue,
                        node,
                    );
                    return;
                }
            }
            if let Some(reference) = stable_identifier_reference(node, ctx.source) {
                if reference.segments.first().is_some_and(|root| {
                    !bindings.resolve_symbol(root).is_unknown() || bindings.is_shadowed(root)
                }) {
                    return;
                }
                let (member, owner_segments) =
                    reference.segments.split_last().expect("stable path");
                let owner_lexical_root = owner_segments
                    .first()
                    .and_then(|root| ctx.lexically_visible_object_unit(node.start_byte(), root));
                if let Some(owner) = ctx.types.resolve_qualified_stable_type_unit_at(
                    ctx.scala,
                    &ctx.resolver,
                    owner_segments,
                    true,
                    owner_lexical_root,
                ) && let Some(field) = ctx.types.exact_field(ctx.scala, &owner.fq_name(), member)
                {
                    ctx.record_exact(field, ScalaReferenceRole::Field, node);
                    return;
                }
                let lexical_root = reference
                    .segments
                    .first()
                    .and_then(|root| ctx.lexically_visible_object_unit(node.start_byte(), root));
                if let Some(object) = ctx.types.resolve_qualified_stable_type_unit_at(
                    ctx.scala,
                    &ctx.resolver,
                    &reference.segments,
                    true,
                    lexical_root,
                ) {
                    ctx.record_exact(object, ScalaReferenceRole::StableObject, node);
                    return;
                }
                // A terminal selection still has exact receiver dispatch below;
                // a stable-path miss must not consume parameterless methods.
                if reference.segments.len() > 1 && !is_terminal_stable_field_reference(node) {
                    return;
                }
            }
            if is_terminal_stable_field_reference(node)
                && let Some(qualifier) = node
                    .parent()
                    .and_then(|expression| expression.child_by_field_name("value"))
            {
                let method_value_expression = node.parent().filter(|expression| {
                    expression.kind() == "field_expression"
                        && expression.child_by_field_name("field") == Some(node)
                });
                let method_value_argument = method_value_expression.filter(|expression| {
                    expression
                        .parent()
                        .is_some_and(|parent| parent.kind() == "arguments")
                });
                let method_value_context = companion_method_value_context(
                    method_value_argument.unwrap_or(node),
                    token,
                    ctx,
                    bindings,
                );
                let unshaped_argument_method_value =
                    matches!(&method_value_context, ScalaMethodValueContext::Unknown)
                        && method_value_argument.is_some();
                let method_value_shape = match method_value_context {
                    ScalaMethodValueContext::Function(shape) => Some(shape),
                    ScalaMethodValueContext::Unknown | ScalaMethodValueContext::Incompatible => {
                        None
                    }
                };
                let call_shape = call_site_shape_for_reference(node)
                    .map(|shape| shape.with_method_value_shape(method_value_shape.clone()))
                    .or_else(|| {
                        method_value_shape.map(|shape| ScalaCallSiteShape {
                            lists: Vec::new(),
                            leading_literal_argument_types: None,
                            method_value_arity: Some(shape.arity),
                            method_value_parameter_types: shape.parameter_types,
                            method_value_parameter_types_authoritative: shape
                                .parameter_types_authoritative,
                            type_arguments_only: false,
                        })
                    });
                if record_union_receiver_parameterless_methods(
                    qualifier, token, name, node, ctx, bindings,
                ) {
                    return;
                }
                if let Some(owner) = receiver_value_owner(qualifier, token, ctx, bindings) {
                    let owner_fqn = match &owner {
                        ScalaValueOwner::Exact(owner) => owner.fq_name(),
                        ScalaValueOwner::Logical(owner) => owner.clone(),
                    };
                    let field_resolution = match &owner {
                        ScalaValueOwner::Exact(owner) => ctx
                            .types
                            .field_for_owner_unit(ctx.scala, token, owner, name),
                        ScalaValueOwner::Logical(owner) => ctx
                            .types
                            .field_for_owner_member(ctx.scala, token, owner, name),
                    };
                    match field_resolution {
                        FieldResolution::Resolved(field) => {
                            ctx.record_exact(field.declaration, ScalaReferenceRole::Field, node);
                        }
                        FieldResolution::Unresolved => return,
                        FieldResolution::NoMatch => {
                            let object = match &owner {
                                ScalaValueOwner::Exact(owner) => ctx
                                    .types
                                    .stable_nested_object_for_owner(ctx.scala, owner, name),
                                ScalaValueOwner::Logical(_) => None,
                            }
                            .or_else(|| {
                                ctx.types
                                    .exact_nested_object_unit(ctx.scala, &owner_fqn, name)
                            });
                            if let Some(object) = object {
                                ctx.record_exact(object, ScalaReferenceRole::StableObject, node);
                                return;
                            }
                            if let ScalaValueOwner::Exact(exact_owner) = &owner {
                                if unshaped_argument_method_value {
                                    match ctx.types.exact_method_value_declaration_for_owner(
                                        ctx.scala,
                                        exact_owner,
                                        name,
                                    ) {
                                        BareMemberResolution::Resolved(methods) => {
                                            for method in methods {
                                                ctx.record_exact_callable(method, node);
                                            }
                                            return;
                                        }
                                        BareMemberResolution::Unresolved => return,
                                        BareMemberResolution::NoMatch => {}
                                    }
                                }
                                let resolution = call_shape.as_ref().map_or_else(
                                    || {
                                        ctx.types.bare_member_declarations_for_owner(
                                            ctx.scala,
                                            token, exact_owner,
                                            name,
                                            None,
                                        )
                                    },
                                    |shape| {
                                        ctx.types
                                            .effective_method_declarations_for_exact_owner_with_shape(
                                                ctx.scala,
                                                token, exact_owner,
                                                name,
                                                shape,
                                            )
                                    },
                                );
                                match resolution {
                                    BareMemberResolution::Resolved(methods) => {
                                        for method in methods {
                                            if let Some(shape) = call_shape.as_ref() {
                                                ctx.record_exact_callable_with_shape(
                                                    method, node, shape,
                                                );
                                            } else {
                                                ctx.record_exact_callable(method, node);
                                            }
                                        }
                                        return;
                                    }
                                    BareMemberResolution::Unresolved => return,
                                    BareMemberResolution::NoMatch => {}
                                }
                            } else if let Some(shape) = call_shape.as_ref() {
                                match ctx
                                    .types
                                    .effective_method_declarations_for_owner_with_shape(
                                        ctx.scala, token, &owner_fqn, name, shape,
                                    ) {
                                    BareMemberResolution::Resolved(methods) => {
                                        for method in methods {
                                            ctx.record_exact_callable_with_shape(
                                                method, node, shape,
                                            );
                                        }
                                        return;
                                    }
                                    BareMemberResolution::Unresolved => return,
                                    BareMemberResolution::NoMatch => {}
                                }
                            } else if record_ordinary_class_methods(
                                &owner_fqn, token, name, None, node, ctx,
                            ) {
                                return;
                            }
                            let extensions =
                                visible_extensions(ctx, token, name, Some(&owner_fqn), None);
                            if !extensions.is_empty() {
                                for extension in extensions {
                                    ctx.record_exact(
                                        extension.declaration,
                                        ScalaReferenceRole::Callable,
                                        node,
                                    );
                                }
                                return;
                            }
                            // The receiver type is proven, but no Scala
                            // declaration of the member exists: a foreign
                            // (Java/Kotlin) owner-member reference (#1859).
                            ctx.record_logical_owner_member(
                                &owner_fqn,
                                name,
                                ScalaReferenceRole::Field,
                                ScalaLogicalReceiver::Instance,
                                call_shape.as_ref(),
                                node,
                            );
                        }
                    }
                } else if let Some(static_owner) = realm_static_owner_fqn(qualifier, ctx, bindings)
                {
                    // The qualifier spells a foreign type itself
                    // (`Stats.origin`): a static-style reference (#1859).
                    ctx.record_logical_owner_member(
                        &static_owner,
                        name,
                        ScalaReferenceRole::Field,
                        ScalaLogicalReceiver::StaticOwner,
                        None,
                        node,
                    );
                    // The same terminal may name a nested foreign type
                    // (`com.example.JarManifest.Section`).
                    if let Some(nested) = ctx.realm_class_fqn(&format!("{static_owner}.{name}")) {
                        ctx.record_logical(nested, ScalaReferenceRole::Type, node);
                    }
                } else {
                    // The qualifier may be a package path, making the whole
                    // selection a foreign type (`com.example.JarManifest`).
                    let mut segments =
                        receiver_static_path_segments(qualifier, ctx.source).unwrap_or_default();
                    segments.push(name.trim_end_matches('$').to_string());
                    if segments.len() > 1
                        && let Some(foreign) =
                            ctx.realm_foreign_type_fqn(&segments, node.start_byte())
                    {
                        ctx.record_logical(foreign, ScalaReferenceRole::Type, node);
                    } else {
                        // A single-name qualifier that the bindings know as an
                        // opaque value is an unproven receiver (#1859); a
                        // package path that names nothing is just not the
                        // target. Query scans only: the edge build has no realm
                        // view and keeps its previous shape here.
                        let value_like = receiver_static_path_segments(qualifier, ctx.source)
                            .is_some_and(|segments| {
                                segments.len() == 1
                                    && segments.first().is_some_and(|head| {
                                        !bindings.resolve_symbol(head).is_unknown()
                                            || bindings.is_shadowed(head)
                                    })
                            });
                        if value_like && ctx.workspace.is_some() {
                            ctx.record_unproven_name(name, node);
                        }
                    }
                }
                return;
            }
            if record_lexically_visible_parameterless_method(node, token, name, ctx) {
                return;
            }
            if is_scala_object_reference(node)
                && bindings.resolve_symbol(name).is_unknown()
                && let Some(target) = ctx.visible_object_reference(node.start_byte(), name)
            {
                ctx.record_resolved(target, ScalaReferenceRole::StableObject, node);
                return;
            }
            if let Some(target) = ctx.resolver.resolve_member_unit(name) {
                ctx.record_exact(
                    target.clone(),
                    if target.is_field() {
                        ScalaReferenceRole::Field
                    } else {
                        ScalaReferenceRole::Callable
                    },
                    node,
                );
            } else if let Some(fqn) = ctx.resolver.resolve_member(name) {
                ctx.record_logical(fqn, ScalaReferenceRole::Callable, node);
            }
        }
        _ => {}
    }
}

fn record_qualified_root_owner_reference(
    node: Node<'_>,
    token: QueryToken<'_>,
    name: &str,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> bool {
    if !is_qualified_stable_root(node)
        || !bindings.resolve_symbol(name).is_unknown()
        || bindings.is_shadowed(name)
    {
        return false;
    }
    let mut recorded = false;
    let object_reference = ctx.visible_object_reference(node.start_byte(), name);
    if let Some(ScalaResolvedReference::Exact(target)) = &object_reference {
        let companions = if target.is_class() && !target.short_name().ends_with('$') {
            ctx.types.exact_companion_objects(ctx.scala, target)
        } else {
            Vec::new()
        };
        if companions.is_empty() {
            ctx.record_exact(target.clone(), ScalaReferenceRole::StableObject, node);
        } else {
            for companion in companions {
                ctx.record_exact(companion, ScalaReferenceRole::StableObject, node);
            }
        }
        recorded = true;
    }
    let type_reference = ctx.visible_type_reference(token, node, name);
    if let Some(ScalaResolvedReference::Exact(target)) = &type_reference
        && (ctx.types.type_is_stable_owner(ctx.scala, target)
            || ctx.types.type_accepts_object_roles(ctx.scala, target))
    {
        let companions = if target.is_class() && !target.short_name().ends_with('$') {
            ctx.types.exact_companion_objects(ctx.scala, target)
        } else {
            Vec::new()
        };
        if companions.is_empty() {
            ctx.record_exact(target.clone(), ScalaReferenceRole::Type, node);
        } else {
            for companion in companions {
                ctx.record_exact(companion, ScalaReferenceRole::StableObject, node);
            }
        }
        recorded = true;
    }
    // The realm fallback is only for a name with no physical answer at all: a
    // resolution the stable-owner rules above declined (an ordinary Scala
    // class qualifier) or a local unindexed binding (a type parameter) is a
    // proven Scala fact, never a foreign type (#1859).
    if !recorded
        && object_reference.is_none()
        && type_reference.is_none()
        && scala_nearest_unindexed_type_binding(ctx.source, node, name.trim_end_matches('$'))
            .is_none()
        && let Some(foreign) =
            ctx.realm_foreign_type_fqn(&[name.trim_end_matches('$').to_string()], node.start_byte())
    {
        // The root of a qualified path names a foreign (Java/Kotlin) type the
        // Scala index does not hold (#1859).
        ctx.record_logical(foreign, ScalaReferenceRole::Type, node);
        return true;
    }
    recorded
}

/// The foreign (non-Scala) resolution of a type reference the physical tiers
/// could not answer (#1859): expand the written path through the file's
/// logical imports and package clauses, prove it against the all-language
/// realm, and record it logically so a foreign-target catalog can match. A
/// `new` site carries its call shape so the sink can apply the Java
/// constructor's arity family. The guards mirror this arm's Scala branches: a
/// name bound or shadowed locally, a declaration name, or a local unindexed
/// type binding is never a foreign type.
fn record_foreign_type_reference(
    node: Node<'_>,
    token: QueryToken<'_>,
    text: &str,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) {
    if ctx.workspace.is_none()
        || !is_scala_class_reference(node, ctx.source)
        || is_declaration_name(node)
        || !bindings.resolve_symbol(text).is_unknown()
        || bindings.is_shadowed(text)
    {
        return;
    }
    // Only a true NoMatch may fall through to the realm: an ambiguous or
    // locally bound name is a deliberate physical answer that no lower tier
    // may overrule.
    if !matches!(
        ctx.exact_lexically_visible_type(token, node),
        ScalaTypeNamespaceResolution::NoMatch
    ) {
        return;
    }
    let lookup = scala_qualified_type_root(node);
    let path = scala_type_lookup_segments(lookup, ctx.source);
    let Some(head) = path.first() else {
        return;
    };
    if scala_nearest_unindexed_type_binding(ctx.source, node, head).is_some() {
        return;
    }
    let Some(foreign) = ctx.realm_foreign_type_fqn(&path, node.start_byte()) else {
        return;
    };
    // A `new` site carries its call shape so the sink can apply the Java
    // constructor's arity family. The argument list belongs to the
    // `instance_expression`, which the shape helper reads from the outermost
    // type node rather than from the leaf.
    if let Some(constructed) = foreign_constructed_type_root(node)
        && let Some(call_shape) = call_site_shape_for_reference(constructed)
    {
        ctx.sink.record_callable(
            ScalaResolvedReference::Logical(foreign),
            ScalaReferenceRole::Type,
            &call_shape,
            classify_reference_node(node),
            UsageHitKind::Reference,
            node.start_byte(),
            node.end_byte(),
        );
        return;
    }
    ctx.record_logical(foreign, ScalaReferenceRole::Type, node);
}

/// The outermost type node of the `new` expression this leaf belongs to, or
/// `None` when the leaf is not the constructed type of any `new`. Only the
/// last segment of a qualified type is the type itself; `lib` in
/// `new lib.Stats()` names a package.
fn foreign_constructed_type_root(node: Node<'_>) -> Option<Node<'_>> {
    let mut constructed = node;
    loop {
        let parent = constructed.parent()?;
        if parent.kind() == "instance_expression" {
            return Some(constructed);
        }
        let wraps_the_constructed_type = match parent.kind() {
            "stable_type_identifier" => {
                let mut cursor = parent.walk();
                parent.named_children(&mut cursor).last() == Some(constructed)
            }
            "generic_type" | "applied_constructor_type" | "annotated_type" | "type" => {
                parent.child_by_field_name("type") == Some(constructed)
                    || parent.named_child(0) == Some(constructed)
            }
            _ => false,
        };
        if !wraps_the_constructed_type {
            return None;
        }
        constructed = parent;
    }
}

fn reference_lookup_name<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    let node = match node.kind() {
        "call_expression" => {
            let function = node.child_by_field_name("function")?;
            let function = invocation_function_reference(function);
            if function.kind() == "field_expression" {
                function.child_by_field_name("field")?
            } else {
                function
            }
        }
        "infix_expression" | "postfix_expression" => node.child_by_field_name("operator")?,
        "identifier" | "operator_identifier" => node,
        _ => return None,
    };
    let name = node_text(node, source).trim();
    (!name.is_empty()).then_some(name)
}

/// Resolve an explicit member import whose owner is a parser-proven local
/// stable value, for example:
///
/// ```scala
/// val cluster = Cluster(system)
/// import cluster.{ selfAddress as localAddress }
/// use(localAddress)
/// ```
///
/// The ordinary name resolver deliberately interprets import paths as global
/// namespaces, so it cannot resolve `cluster.selfAddress`. The local inference
/// environment already carries the exact physical declaration returned by the
/// `Cluster(...)` application; bridge the parser-recorded import path to that
/// declaration without reconstructing or scanning source text. A matching
/// local-root import is authoritative: imprecise owners, missing members, or
/// conflicting visible imports consume the name and fail closed rather than
/// falling through to an unrelated global member with the same spelling.
fn record_local_stable_imported_member(
    node: Node<'_>,
    token: QueryToken<'_>,
    visible_name: &str,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> bool {
    if bindings.is_shadowed(visible_name) {
        return false;
    }

    let mut matched_local_import = false;
    let mut selected_targets: Option<Vec<CodeUnit>> = None;
    for import in ctx.imports.iter().filter(|import| {
        !import.is_wildcard && scala_import_is_visible_at_byte(import, node.start_byte())
    }) {
        if import.identifier.as_deref() != Some(visible_name) {
            continue;
        }
        let Some(path) = import.path.as_ref() else {
            continue;
        };
        let Some((member, owner_path)) = path.segments.split_last() else {
            continue;
        };
        let Some(root_name) = owner_path.first() else {
            continue;
        };
        if !bindings.is_shadowed(root_name) {
            continue;
        }
        matched_local_import = true;

        let Some(binding) = precise_scala_binding(bindings, root_name) else {
            return true;
        };
        let Some(mut owner) = binding.receiver_declaration.or_else(|| {
            let receiver_type = binding.receiver_type.as_deref()?;
            let declarations = ctx.types.index.by_fqn(receiver_type);
            let mut candidates = declarations.iter().filter(|unit| unit.is_class());
            let declaration = candidates.next()?.clone();
            candidates.next().is_none().then_some(declaration)
        }) else {
            return true;
        };
        for segment in &owner_path[1..] {
            let Some(nested) = ctx
                .types
                .exact_nested_object_for_owner(ctx.scala, &owner, segment)
            else {
                return true;
            };
            owner = nested;
        }

        let mut targets = match ctx
            .types
            .field_for_owner_unit(ctx.scala, token, &owner, member)
        {
            FieldResolution::Resolved(field) => vec![field.declaration],
            FieldResolution::Unresolved => return true,
            FieldResolution::NoMatch => {
                if let Some(object) = ctx
                    .types
                    .exact_nested_object_for_owner(ctx.scala, &owner, member)
                {
                    vec![object]
                } else {
                    match ctx
                        .types
                        .bare_member_declarations_for_owner(ctx.scala, token, &owner, member, None)
                    {
                        BareMemberResolution::Resolved(methods) if !methods.is_empty() => methods,
                        BareMemberResolution::Resolved(_)
                        | BareMemberResolution::NoMatch
                        | BareMemberResolution::Unresolved => return true,
                    }
                }
            }
        };
        targets.sort();
        targets.dedup();
        if selected_targets
            .as_ref()
            .is_some_and(|selected| selected != &targets)
        {
            return true;
        }
        selected_targets = Some(targets);
    }

    if !matched_local_import {
        return false;
    }
    for target in selected_targets.into_iter().flatten() {
        let role = if target.is_field() {
            ScalaReferenceRole::Field
        } else if target.is_function() {
            ScalaReferenceRole::Callable
        } else {
            ScalaReferenceRole::StableObject
        };
        ctx.record_exact(target, role, node);
    }
    true
}

fn record_explicit_imported_member(
    node: Node<'_>,
    visible_name: &str,
    ctx: &mut ScalaScan<'_, '_>,
) -> bool {
    let mut matched_import = false;
    let mut selected_targets: Option<Vec<CodeUnit>> = None;
    for import in ctx.imports.iter().filter(|import| {
        !import.is_wildcard
            && scala_import_is_visible_at_byte(import, node.start_byte())
            && import.local_name() == Some(visible_name)
    }) {
        let Some(path) = import.path.as_ref() else {
            continue;
        };
        let mut targets = resolve_exact_import_path_references(
            &path.segments,
            path.declaration_start_byte,
            true,
            ctx,
        );
        targets.retain(|target| {
            target.is_function()
                || target.is_field()
                || target.short_name().ends_with('$')
                || (target.is_class() && ctx.types.type_accepts_object_roles(ctx.scala, target))
        });
        if is_bare_companion_method_value_reference(node) {
            targets.retain(|target| !target.is_class() || target.short_name().ends_with('$'));
            if targets.is_empty() {
                continue;
            }
        }
        matched_import = true;
        targets.sort();
        targets.dedup();
        if selected_targets
            .as_ref()
            .is_some_and(|selected| selected != &targets)
        {
            return true;
        }
        selected_targets = Some(targets);
    }

    let Some(targets) = selected_targets else {
        return matched_import;
    };
    for target in targets {
        let role = if target.is_function() {
            ScalaReferenceRole::Callable
        } else if target.is_field() {
            ScalaReferenceRole::Field
        } else {
            ScalaReferenceRole::StableObject
        };
        ctx.record_exact(target, role, node);
    }
    matched_import
}

fn record_union_receiver_parameterless_methods(
    receiver: Node<'_>,
    token: QueryToken<'_>,
    member: &str,
    node: Node<'_>,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> bool {
    if receiver.kind() != "identifier" {
        return false;
    }
    let Some(receiver_bindings) = bindings
        .resolve_symbol_ref(node_text(receiver, ctx.source))
        .and_then(|resolution| resolution.as_precise())
        .filter(|bindings| bindings.len() > 1)
    else {
        return false;
    };
    let mut methods = Vec::new();
    for binding in receiver_bindings {
        let owner = binding
            .receiver_declaration
            .as_ref()
            .map(|owner| ScalaValueOwner::Exact(owner.clone()))
            .or_else(|| {
                binding
                    .receiver_type
                    .as_ref()
                    .map(|owner| ScalaValueOwner::Logical(owner.clone()))
            });
        let Some(owner) = owner else {
            return true;
        };
        let resolution = match &owner {
            ScalaValueOwner::Exact(owner) => {
                ctx.types.effective_method_declarations_for_exact_owner(
                    ctx.scala, token, owner, member, None,
                )
            }
            ScalaValueOwner::Logical(owner) => ctx
                .types
                .effective_method_declarations_for_owner(ctx.scala, token, owner, member, None),
        };
        let mut resolved = match resolution {
            BareMemberResolution::Resolved(resolved) => resolved,
            BareMemberResolution::NoMatch | BareMemberResolution::Unresolved => {
                let resolution = match &owner {
                    ScalaValueOwner::Exact(owner) => ctx
                        .types
                        .field_for_owner_unit(ctx.scala, token, owner, member),
                    ScalaValueOwner::Logical(owner) => ctx
                        .types
                        .field_for_owner_member(ctx.scala, token, owner, member),
                };
                match resolution {
                    FieldResolution::Resolved(field) => vec![field.declaration],
                    FieldResolution::NoMatch | FieldResolution::Unresolved => return true,
                }
            }
        };
        if resolved.is_empty() {
            return true;
        }
        let field_owners = resolved
            .iter()
            .filter(|declaration| declaration.is_field())
            .filter_map(|field| ctx.types.exact_structural_parent(ctx.scala, field))
            .collect::<Vec<_>>();
        for field_owner in field_owners {
            for ancestor in ctx.types.exact_ancestors(&field_owner) {
                resolved.extend(
                    ctx.types
                        .exact_member_declarations(ctx.scala, &ancestor, member)
                        .into_iter()
                        .filter(|declaration| {
                            declaration.is_function()
                                && ctx
                                    .types
                                    .exact_structural_parent(ctx.scala, declaration)
                                    .as_ref()
                                    == Some(&ancestor)
                        }),
                );
            }
        }
        let receiver_owners = match &owner {
            ScalaValueOwner::Exact(owner) => vec![owner.clone()],
            ScalaValueOwner::Logical(owner) => ctx
                .types
                .index
                .by_fqn(owner)
                .iter()
                .filter(|declaration| declaration.is_class())
                .cloned()
                .collect(),
        };
        if let [receiver_owner] = receiver_owners.as_slice() {
            for ancestor in ctx.types.exact_ancestors(receiver_owner) {
                resolved.extend(
                    ctx.types
                        .exact_member_declarations(ctx.scala, &ancestor, member)
                        .into_iter()
                        .filter(|declaration| {
                            declaration.is_function()
                                && ctx
                                    .types
                                    .exact_structural_parent(ctx.scala, declaration)
                                    .as_ref()
                                    == Some(&ancestor)
                        }),
                );
            }
        }
        methods.extend(resolved);
    }
    methods.sort();
    methods.dedup();
    for method in methods {
        ctx.record_exact_callable(method, node);
    }
    true
}

/// Resolve a parser-recorded stable path such as `pkg.helper(...)` directly to
/// exact workspace callables. Receiver inference intentionally treats package
/// roots as namespaces rather than value types, so this path is handled only
/// after ordinary receiver/member resolution has failed.
fn record_qualified_package_call(
    field: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut ScalaScan<'_, '_>,
) -> bool {
    let Some(reference) = qualified_stable_type_reference(field, ctx.source) else {
        return false;
    };
    if reference.segments.len() < 2 {
        return false;
    }
    let Some(call_shape) = call_site_shape_for_reference(field) else {
        return false;
    };
    let fqn = reference.segments.join(".");
    let methods = ctx
        .types
        .imported_member_targets_with_shape(ctx.scala, token, &fqn, &call_shape);
    if methods.is_empty() {
        return false;
    }
    for method in methods {
        ctx.record_exact_callable(method, field);
    }
    true
}

/// Record an unqualified owner field used as an application/indexing function.
///
/// Tree-sitter gives `values(index)` to the enclosing `call_expression`; the
/// identifier child is intentionally not revisited because doing so would lose
/// callable shape. Preserve that ownership while still emitting the exact field
/// selection before ordinary method/type-application dispatch. Local parameters
/// and local values remain authoritative shadows.
fn record_unqualified_applied_field(
    function: Node<'_>,
    token: QueryToken<'_>,
    name: &str,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> LexicalFieldReferenceResolution {
    match record_lexically_visible_field_reference(function, token, name, ctx, bindings) {
        LexicalFieldReferenceResolution::Consumed => {
            return LexicalFieldReferenceResolution::Consumed;
        }
        LexicalFieldReferenceResolution::CallableBound => {
            return LexicalFieldReferenceResolution::CallableBound;
        }
        LexicalFieldReferenceResolution::NoMatch => {}
    }
    if let Some(target) = ctx.resolver.resolve_member_unit(name)
        && ctx.types.has_term_field_declaration(&target)
        && !ctx.types.is_type_alias(ctx.scala, &target)
    {
        ctx.record_exact(target, ScalaReferenceRole::Field, function);
        return LexicalFieldReferenceResolution::Consumed;
    }
    LexicalFieldReferenceResolution::NoMatch
}

/// Calls and infix expressions resolve callable shape at their owning AST
/// node. Their member/operator child must not be revisited as an unshaped
/// stable reference, which could otherwise resurrect an inapplicable overload.
fn reference_is_owned_by_invocation(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() == "infix_expression" && parent.child_by_field_name("operator") == Some(node) {
        return true;
    }
    if parent.kind() == "postfix_expression" && scala_postfix_operator_node(parent) == Some(node) {
        return true;
    }
    parent.kind() == "field_expression"
        && parent.child_by_field_name("field") == Some(node)
        && is_call_function_reference(parent)
}

fn scala_postfix_operator_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let mut operator = None;
    for child in node.named_children(&mut cursor) {
        if matches!(child.kind(), "identifier" | "operator_identifier") {
            operator = Some(child);
        }
    }
    operator
}

fn scala_postfix_receiver_node<'tree>(
    node: Node<'tree>,
    operator: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.end_byte() <= operator.start_byte())
}

/// Whether `name` at this pattern site denotes an extractor owner: a type whose
/// companion (or the case class itself) supplies the extractor, or an object
/// that declares `unapply`/`unapplySeq` of its own.
///
/// An extractor lives in Scala's term namespace, so an object with no companion
/// class -- `object Split { def unapply(..) }`, the shape the infix pattern
/// `case left Split right` writes -- owns the pattern even though the type
/// namespace knows nothing by that name (#2078).
fn names_extractor_owner(
    node: Node<'_>,
    token: QueryToken<'_>,
    name: &str,
    ctx: &ScalaScan<'_, '_>,
) -> bool {
    if let Some(fqn) = ctx.visible_type(token, node, name)
        && let Some(target) = ctx
            .types
            .type_by_normalized_fqn(&scala_normalized_fq_name(&fqn))
        && ctx.types.class_accepts_extractor_role(ctx.scala, &target)
    {
        return true;
    }
    ctx.lexically_visible_object_unit(node.start_byte(), name)
        .or_else(|| ctx.resolver.resolve_object_unit(name))
        .is_some_and(|object| ctx.types.declares_extractor_entry_point(ctx.scala, &object))
}

fn record_unqualified_type_application(
    function: Node<'_>,
    token: QueryToken<'_>,
    name: &str,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> bool {
    let application_role =
        if is_extractor_reference(function) || is_infix_pattern_operator(function) {
            TypeApplicationRole::Extractor
        } else {
            TypeApplicationRole::BareApplication
        };
    let Some((resolution, call_shape)) = resolve_unqualified_type_application(
        function,
        token,
        name,
        application_role,
        ctx,
        bindings,
    ) else {
        return false;
    };
    if let Some(target) = resolution.type_target {
        ctx.record_exact(target.clone(), ScalaReferenceRole::Type, function);
        let exact_companions = ctx.types.exact_companion_objects(ctx.scala, &target);
        let has_exact_companion_callable = resolution.callable_targets.iter().any(|callable| {
            ctx.scala
                .structural_parent_of(callable)
                .is_some_and(|owner| exact_companions.contains(&owner))
        });
        if application_role == TypeApplicationRole::BareApplication && !has_exact_companion_callable
        {
            for constructor in ctx
                .types
                .exact_member_declarations(ctx.scala, &target, target.identifier())
                .into_iter()
                .filter(CodeUnit::is_synthetic)
                .filter(|constructor| {
                    ctx.types.constructor_target_matches(
                        ctx.scala,
                        token,
                        constructor,
                        call_shape.as_ref(),
                        ScalaCallableSiteRole::PrimaryConstruction,
                    )
                })
            {
                ctx.record_exact_companion_callable(
                    constructor,
                    ScalaReferenceRole::CompanionApplication,
                    function,
                );
            }
        }
    }
    for callable in resolution.callable_targets {
        ctx.record_exact_companion_callable(
            callable,
            if application_role == TypeApplicationRole::Extractor {
                ScalaReferenceRole::CompanionExtractor
            } else {
                ScalaReferenceRole::CompanionApplication
            },
            function,
        );
    }
    true
}

fn resolve_unqualified_type_application(
    function: Node<'_>,
    token: QueryToken<'_>,
    name: &str,
    role: TypeApplicationRole,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> Option<(TypeApplicationResolution, Option<ScalaCallSiteShape>)> {
    if !bindings.resolve_symbol(name).is_unknown() || bindings.is_shadowed(name) {
        return None;
    }
    let class_fqn = ctx.visible_type(token, function, name);
    let object_fqn = ctx
        .lexically_visible_object(function.start_byte(), name)
        .or_else(|| ctx.resolver.resolve_object(name));
    if class_fqn.is_none() && object_fqn.is_none() {
        return None;
    }
    let call_shape = call_site_shape_for_reference(function);
    let resolution = ctx.types.resolve_type_application(
        ctx.scala,
        token,
        &ctx.resolver,
        class_fqn.as_deref(),
        object_fqn.as_deref(),
        name,
        call_shape.as_ref(),
        role,
        Some(ctx.source_file),
    );
    Some((resolution, call_shape))
}

/// Whether `field` is the member of a `super.member` selection.
fn is_super_selection(field: Node<'_>, source: &str) -> bool {
    field
        .parent()
        .filter(|parent| {
            parent.kind() == "field_expression"
                && parent.child_by_field_name("field") == Some(field)
        })
        .and_then(|parent| parent.child_by_field_name("value"))
        .is_some_and(|value| node_text(value, source).trim() == "super")
}

/// Record what `super.member` names inside the enclosing template. The up-call
/// is answered by the template's parent linearization, never by its own
/// override, and an unresolved one records nothing rather than falling through
/// to a receiver rule that would read `super` as an ordinary value.
fn record_super_member(
    node: Node<'_>,
    token: QueryToken<'_>,
    name: &str,
    ctx: &mut ScalaScan<'_, '_>,
) {
    let Some(owner) = ctx.enclosing_class_unit(node.start_byte()).cloned() else {
        return;
    };
    let call_shape = call_site_shape_for_reference(node);
    let call = match call_shape.as_ref() {
        Some(shape) => ScalaCallMatch::Shape(shape),
        None => ScalaCallMatch::Arities(None),
    };
    if let BareMemberResolution::Resolved(methods) = ctx
        .types
        .super_method_declarations(ctx.scala, token, &owner, name, call)
    {
        for method in methods {
            match call_shape.as_ref() {
                Some(shape) => ctx.record_exact_callable_with_shape(method, node, shape),
                None => ctx.record_exact(method, ScalaReferenceRole::Callable, node),
            }
        }
    }
}

/// `C.apply(args)` on a case class. Bifrost identifies a case class's synthetic
/// companion `apply` with the class's primary constructor, and `get_definition`
/// answers the selection with that constructor, so the inverse records it too.
/// Ordinary member lookup cannot: the companion declares no `apply` unit, and an
/// `apply` the companion inherits from a supertype is not the callee.
fn record_explicit_case_class_apply(
    receiver: Node<'_>,
    token: QueryToken<'_>,
    field: Node<'_>,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> bool {
    let Some(owner) = receiver_type_declaration(receiver, token, ctx, bindings).or_else(|| {
        let name = node_text(receiver, ctx.source).trim();
        if receiver.kind() != "identifier"
            || !bindings.resolve_symbol(name).is_unknown()
            || bindings.is_shadowed(name)
        {
            return None;
        }
        match ctx.visible_type_reference(token, receiver, name) {
            Some(ScalaResolvedReference::Exact(unit)) => Some(unit),
            Some(ScalaResolvedReference::Logical(_)) | None => None,
        }
    }) else {
        return false;
    };
    let Some(class) = ctx.types.synthetic_apply_case_class(ctx.scala, &owner) else {
        return false;
    };
    let resolution = ctx.types.resolve_type_application(
        ctx.scala,
        token,
        &ctx.resolver,
        Some(&class.fq_name()),
        None,
        &scala_short_name_terminal_segment(class.short_name()),
        call_site_shape_for_reference(field).as_ref(),
        TypeApplicationRole::BareApplication,
        Some(ctx.source_file),
    );
    if resolution.callable_targets.is_empty() {
        return false;
    }
    for callable in resolution.callable_targets {
        ctx.record_exact_companion_callable(
            callable,
            ScalaReferenceRole::CompanionApplication,
            field,
        );
    }
    true
}

/// A case class's `copy` parameters are compiler-generated from the authored
/// constructor parameters. Record those source fields directly; `copy` itself
/// has no inverse-usage identity because there is no physical method CodeUnit.
fn record_case_class_copy(
    receiver: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> bool {
    case_class_copy_owner(receiver, token, ctx, bindings).is_some()
}

fn case_class_copy_owner(
    receiver: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> Option<CodeUnit> {
    let owner = receiver_type_declaration(receiver, token, ctx, bindings)?;
    ctx.types.is_case_class(ctx.scala, &owner).then_some(owner)
}

/// The callables a named argument's label can name, given the invocation's
/// terminal callee-name node.
///
/// Ordinary call resolution runs first for every supported invocation shape --
/// a receiver method call, an unqualified method call, a companion
/// application, and an explicit constructor -- and registers what it proved.
/// The label narrows that proven set to the callables that declare a parameter
/// with this label, so an overload family that arity or literal filtering has
/// already reduced stays reduced. An invocation whose callee never resolved has
/// no registered callable and therefore contributes no label reference.
fn named_argument_callable_targets(
    function: Node<'_>,
    label: &str,
    ctx: &ScalaScan<'_, '_>,
) -> Vec<CodeUnit> {
    let Some(callables) = ctx.invocation_callables.get(&function.id()) else {
        return Vec::new();
    };
    let mut targets = callables
        .iter()
        .filter(|callable| {
            ctx.types
                .signature_metadata_for(ctx.scala, callable)
                .iter()
                .flat_map(|metadata| metadata.parameters())
                .any(|parameter| parameter.label() == label)
        })
        .cloned()
        .collect::<Vec<_>>();
    targets.sort();
    targets.dedup();
    targets
}

/// The declaration a projection's selector names, when `node` is that selector.
///
/// `Owner#Member` gives the member its own `type_identifier` under a
/// `projected_type`, and no stable-path helper reaches it:
/// `qualified_stable_type_reference` reads `stable_type_identifier` and
/// `stable_identifier` parents only, so scalaz's `IterateeTF[F]#λ` recorded the
/// projected owner and nothing for the type member it selects. Resolve the
/// owner as an ordinary type reference -- the parser gives it the
/// `projected_type`'s `type` field, and `scala_type_lookup_segments` already
/// drops its type arguments -- and read the member from its linearization.
fn projected_type_member_declaration(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
) -> Option<CodeUnit> {
    let owner_node = node
        .parent()
        .filter(|parent| parent.kind() == "projected_type")?
        .child_by_field_name("type")?;
    // A projection's owner is a complete type expression, but
    // `scala_qualified_type_root` climbs through `projected_type` and so reads
    // `Inner[F]#l` as the two-segment path `Inner.l`. The lexical tier keys off
    // the root segment alone and stays correct there; only the whole-path
    // lookup above it has to be bypassed, which is why a lexically nested owner
    // such as scalaz's `trait IterateeTF` inside `trait IterateeTHoist` needs
    // this tier before the ordinary namespace route.
    let owner = match scala_type_lookup_segments(owner_node, ctx.source).as_slice() {
        [_] => match ctx.exact_lexically_visible_type_root(token, owner_node) {
            ScalaTypeNamespaceResolution::Resolved(declaration) => Some(declaration),
            ScalaTypeNamespaceResolution::AuthoritativeMiss
            | ScalaTypeNamespaceResolution::Ambiguous(_) => return None,
            ScalaTypeNamespaceResolution::NoMatch => {
                resolve_receiver_type_declaration_node(owner_node, token, ctx)
            }
        },
        _ => resolve_receiver_type_declaration_node(owner_node, token, ctx),
    }?;
    ctx.types
        .projected_type_member(ctx.scala, &owner, node_text(node, ctx.source).trim())
}

fn record_qualified_stable_reference(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> bool {
    let Some(reference) = qualified_stable_type_reference(node, ctx.source) else {
        return false;
    };
    if reference.segments.is_empty() {
        return true;
    }
    if reference.role == ScalaQualifiedStableTypeRole::Type
        && let [owner_name, this_segment, member] = reference.segments.as_slice()
        && this_segment == "this"
    {
        let mut matches = Vec::new();
        let mut enclosing = ctx.enclosing_class_unit(node.start_byte()).cloned();
        while let Some(owner) = enclosing {
            enclosing = ctx.types.exact_structural_parent(ctx.scala, &owner);
            if owner.is_class() && scala_simple_type_name(&owner) == *owner_name {
                matches.push(owner);
            }
        }
        if let [owner] = matches.as_slice()
            && let FieldResolution::Resolved(field) = ctx
                .types
                .stable_type_member_for_owner_unit(ctx.scala, token, owner, member)
        {
            let role = if ctx.types.is_type_alias(ctx.scala, &field.declaration) {
                ScalaReferenceRole::Type
            } else {
                ScalaReferenceRole::Field
            };
            ctx.record_exact(field.declaration, role, node);
        }
        return true;
    }
    if reference
        .segments
        .first()
        .is_some_and(|root| bindings.is_shadowed(root))
    {
        return reference.role == ScalaQualifiedStableTypeRole::Type
            && !is_terminal_stable_field_reference(node);
    }
    // In a qualified extractor such as `Domain.Continuous(value)`, the stable
    // enum/type root is an independently meaningful reference in addition to
    // the terminal extractor. Preserve the complete parser expression as the
    // hit range so exact forward sites covering the qualified extractor round
    // trip. A cross-built root is one logical symbol with several physical
    // homes, so the reference is recorded against every family member (#2021);
    // an incoherent candidate set resolves to nothing and stays ambiguous.
    //
    // `type_is_stable_owner` is asked per member rather than once for the
    // family on purpose: family membership says the units are the same symbol,
    // it does not say every member satisfies an independent structural
    // property.
    if reference.role == ScalaQualifiedStableTypeRole::Extractor
        && reference.segments.len() > 1
        && let Some(root) = reference.segments.first()
    {
        for target in ctx.resolver.resolve_units(root) {
            if ctx.types.type_is_stable_owner(ctx.scala, &target) {
                ctx.record_exact(target, ScalaReferenceRole::Type, reference.expression);
            }
        }
    }
    let lexical_object_root = reference
        .segments
        .first()
        .and_then(|root| ctx.lexically_visible_object_unit(node.start_byte(), root));
    // Term-shaped stable applications hand us the terminal field node, so the
    // generic type-root helper would interpret `UserInfo` as the root of
    // `Uri.UserInfo(...)`. An exact lexical object for the parser-proven first
    // segment is stronger evidence and owns this stable path.
    let term_application_lexical_object =
        reference.expression.kind() == "field_expression" && lexical_object_root.is_some();
    let lexical_type_root = if term_application_lexical_object {
        ScalaTypeNamespaceResolution::NoMatch
    } else {
        ctx.exact_lexically_visible_type_root(token, node)
    };
    let class_lookup_blocked = matches!(
        lexical_type_root,
        ScalaTypeNamespaceResolution::AuthoritativeMiss
            | ScalaTypeNamespaceResolution::Ambiguous(_)
    );
    let lexical_roots = match &lexical_type_root {
        ScalaTypeNamespaceResolution::Resolved(declaration) => {
            let mut roots = ctx.types.exact_companion_objects(ctx.scala, declaration);
            if ctx.types.type_is_stable_owner(ctx.scala, declaration) {
                roots.push(declaration.clone());
            }
            roots.sort();
            roots.dedup();
            roots
        }
        ScalaTypeNamespaceResolution::NoMatch => {
            let root = reference.segments.first().expect("qualified stable root");
            if term_application_lexical_object {
                lexical_object_root.into_iter().collect()
            } else {
                let mut roots =
                    ctx.types
                        .stable_roots_for_resolved_type_name(ctx.scala, &ctx.resolver, root);
                if roots.is_empty()
                    && let Some(object) = lexical_object_root
                {
                    roots.push(object);
                }
                roots
            }
        }
        ScalaTypeNamespaceResolution::AuthoritativeMiss
        | ScalaTypeNamespaceResolution::Ambiguous(_) => Vec::new(),
    };
    let class_unit = (!class_lookup_blocked)
        .then(|| {
            ctx.types
                .resolve_qualified_stable_type_unit_at_with_lexical_roots(
                    ctx.scala,
                    &ctx.resolver,
                    &reference.segments,
                    false,
                    lexical_roots.clone(),
                )
        })
        .flatten();
    let object_unit = ctx
        .types
        .resolve_qualified_stable_type_unit_at_with_lexical_roots(
            ctx.scala,
            &ctx.resolver,
            &reference.segments,
            true,
            lexical_roots,
        );
    if class_unit.is_none()
        && !class_lookup_blocked
        && reference.role == ScalaQualifiedStableTypeRole::Type
        && let Some((member, owner_segments)) = reference.segments.split_last()
    {
        if owner_segments.is_empty() {
            return false;
        }
        let owner_lexical_root = owner_segments
            .first()
            .and_then(|root| ctx.lexically_visible_object_unit(node.start_byte(), root));
        if let Some(owner) = ctx.types.resolve_qualified_stable_type_unit_at(
            ctx.scala,
            &ctx.resolver,
            owner_segments,
            true,
            owner_lexical_root,
        ) && let FieldResolution::Resolved(field) = ctx
            .types
            .stable_type_member_for_owner_unit(ctx.scala, token, &owner, member)
        {
            let role = if ctx.types.is_type_alias(ctx.scala, &field.declaration) {
                ScalaReferenceRole::Type
            } else {
                ScalaReferenceRole::Field
            };
            ctx.record_exact(field.declaration, role, node);
            return true;
        }
    }
    if reference.role == ScalaQualifiedStableTypeRole::Type {
        if class_lookup_blocked {
            return true;
        }
        if let Some(target) = class_unit {
            ctx.record_exact(target, ScalaReferenceRole::Type, node);
        } else if let Some(target) = object_unit {
            ctx.record_exact(target, ScalaReferenceRole::StableObject, node);
        } else if let Some(foreign) =
            ctx.realm_foreign_type_fqn(&reference.segments, node.start_byte())
        {
            // A qualified type path no Scala tier could resolve names a
            // foreign (Java/Kotlin) type when the realm proves it (#1859).
            ctx.record_logical(foreign, ScalaReferenceRole::Type, node);
        }
        return true;
    }
    if class_unit.is_none() && object_unit.is_none() {
        if reference.role != ScalaQualifiedStableTypeRole::Type {
            // A bare extractor can be an inherited stable `val` (for example
            // Akka FSM's `Event`). Type/object lookup owns qualified misses,
            // but application-shaped misses must continue into exact receiver,
            // lexical-field, or extension resolution below.
            return false;
        }
        return true;
    }
    let role = match reference.role {
        ScalaQualifiedStableTypeRole::Constructor => TypeApplicationRole::ExplicitConstructor,
        ScalaQualifiedStableTypeRole::Apply => TypeApplicationRole::BareApplication,
        ScalaQualifiedStableTypeRole::Extractor => TypeApplicationRole::Extractor,
        ScalaQualifiedStableTypeRole::Type => unreachable!(),
    };
    if role == TypeApplicationRole::ExplicitConstructor
        && let Some(alias) = class_unit
            .as_ref()
            .filter(|unit| ctx.types.is_type_alias(ctx.scala, unit))
    {
        ctx.record_exact(alias.clone(), ScalaReferenceRole::Type, node);
        return true;
    }
    let name = reference
        .segments
        .last()
        .expect("qualified Scala reference has a terminal segment");
    let class_fqn = class_unit.as_ref().map(CodeUnit::fq_name);
    let object_fqn = object_unit.as_ref().map(CodeUnit::fq_name);
    let resolution = ctx.types.resolve_type_application(
        ctx.scala,
        token,
        &ctx.resolver,
        class_fqn.as_deref(),
        object_fqn.as_deref(),
        name,
        call_site_shape_for_reference(reference.expression).as_ref(),
        role,
        Some(ctx.source_file),
    );
    if let Some(target) = resolution.type_target {
        ctx.record_exact(target.clone(), ScalaReferenceRole::Type, node);
        let exact_companions = ctx.types.exact_companion_objects(ctx.scala, &target);
        let has_exact_companion_callable = resolution.callable_targets.iter().any(|callable| {
            ctx.scala
                .structural_parent_of(callable)
                .is_some_and(|owner| exact_companions.contains(&owner))
        });
        if role == TypeApplicationRole::BareApplication && !has_exact_companion_callable {
            for constructor in ctx
                .types
                .exact_member_declarations(ctx.scala, &target, target.identifier())
                .into_iter()
                .filter(CodeUnit::is_synthetic)
                .filter(|constructor| {
                    ctx.types.constructor_target_matches(
                        ctx.scala,
                        token,
                        constructor,
                        call_site_shape_for_reference(reference.expression).as_ref(),
                        ScalaCallableSiteRole::PrimaryConstruction,
                    )
                })
            {
                ctx.record_exact_companion_callable(
                    constructor,
                    ScalaReferenceRole::CompanionApplication,
                    node,
                );
            }
        }
    }
    for callable in resolution.callable_targets {
        if role == TypeApplicationRole::ExplicitConstructor {
            ctx.record_exact_callable(callable, node);
        } else {
            ctx.record_exact_companion_callable(
                callable,
                if role == TypeApplicationRole::Extractor {
                    ScalaReferenceRole::CompanionExtractor
                } else {
                    ScalaReferenceRole::CompanionApplication
                },
                node,
            );
        }
    }
    true
}

fn record_intermediate_stable_object_reference(
    node: Node<'_>,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> bool {
    let Some(reference) = intermediate_field_qualifier_reference(node, ctx.source)
        .or_else(|| stable_identifier_prefix_reference(node, ctx.source))
        .or_else(|| stable_type_prefix_reference(node, ctx.source))
    else {
        return false;
    };
    let Some(root) = reference.segments.first() else {
        return false;
    };
    if !bindings.resolve_symbol(root).is_unknown() || bindings.is_shadowed(root) {
        // Local and parameter roots belong to the established structured
        // receiver-chain paths below, not to namespace-rooted stable objects.
        return false;
    }
    let mut lexical_roots = Vec::new();
    // A cross-built root is one logical symbol with several physical homes
    // (#2021); each member contributes its own companion objects, and the
    // stable-owner question is asked per member because family membership does
    // not confer an independent structural property.
    for declaration in ctx.resolver.resolve_units(root) {
        lexical_roots.extend(ctx.types.exact_companion_objects(ctx.scala, &declaration));
        if ctx.types.type_is_stable_owner(ctx.scala, &declaration) {
            lexical_roots.push(declaration);
        }
    }
    if let Some(object) = ctx
        .lexically_visible_object_unit(node.start_byte(), root)
        .or_else(|| ctx.resolver.resolve_object_unit(root))
    {
        lexical_roots.push(object);
    }
    if lexical_roots.is_empty() {
        lexical_roots =
            ctx.types
                .stable_roots_for_resolved_type_name(ctx.scala, &ctx.resolver, root);
        if lexical_roots.is_empty()
            && let Some(object) = ctx.lexically_visible_object_unit(node.start_byte(), root)
        {
            lexical_roots.push(object);
        }
    }
    lexical_roots.sort();
    lexical_roots.dedup();
    if let Some(target) = ctx
        .types
        .resolve_qualified_stable_type_unit_at_with_lexical_roots(
            ctx.scala,
            &ctx.resolver,
            &reference.segments,
            true,
            lexical_roots.clone(),
        )
    {
        ctx.record_exact(target, ScalaReferenceRole::StableObject, node);
        return true;
    }
    // A case class carries an implicit companion, which the index models as
    // the class declaration itself: `Owner.Failed.apply` selects through
    // `Failed` without any `Failed$` unit existing (#2082). Resolve the same
    // path in the type namespace and keep only a declaration that genuinely
    // accepts object roles, so an ordinary nested class stays unrecorded.
    if let Some(target) = ctx
        .types
        .resolve_qualified_stable_type_unit_at_with_lexical_roots(
            ctx.scala,
            &ctx.resolver,
            &reference.segments,
            false,
            lexical_roots,
        )
        .filter(|target| ctx.types.type_accepts_object_roles(ctx.scala, target))
    {
        // The index carries no companion unit for that class, so `Type` is
        // the role its identity answers to.
        ctx.record_exact(target, ScalaReferenceRole::Type, node);
        return true;
    }
    // This parser shape also covers ordinary field chains such as
    // `Owner.this.service.run` and `state.payload.value`. An unresolved object
    // prefix is therefore not authoritative; let the exact receiver/field
    // paths below retain ownership.
    false
}

/// Record a stable field path rooted in a parser-proven local binding. Namespace
/// lookup deliberately rejects shadowed roots, so a path such as
/// `repr.qctx.type` must instead start from `repr`'s inferred receiver type and
/// traverse the fields carried by the stable identifier AST. Field lookup stays
/// fail-closed when that logical receiver has multiple physical declarations.
fn record_local_stable_field_reference(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> bool {
    let segments = stable_identifier_prefix_reference(node, ctx.source)
        .map(|reference| reference.segments)
        .or_else(|| {
            qualified_stable_type_reference(node, ctx.source)
                .filter(|reference| reference.role == ScalaQualifiedStableTypeRole::Type)
                .map(|reference| reference.segments)
        })
        .or_else(|| {
            let expression = node.parent().filter(|parent| {
                parent.kind() == "field_expression"
                    && parent.child_by_field_name("field") == Some(node)
            })?;
            let mut segments = vec![node_text(node, ctx.source).trim().to_string()];
            let mut value = expression.child_by_field_name("value")?;
            while value.kind() == "field_expression" {
                let field = value.child_by_field_name("field")?;
                let segment = node_text(field, ctx.source).trim();
                if segment.is_empty() {
                    return None;
                }
                segments.push(segment.to_string());
                value = value.child_by_field_name("value")?;
            }
            if !matches!(value.kind(), "identifier" | "type_identifier") {
                return None;
            }
            let root = node_text(value, ctx.source).trim();
            if root.is_empty() {
                return None;
            }
            segments.push(root.to_string());
            segments.reverse();
            // A one-hop `value.member` selection belongs to ordinary receiver
            // dispatch, including union-typed parameters. This helper exists
            // for the nested stable-owner shape that receiver dispatch cannot
            // otherwise carry across (for example
            // `owner.Filters.authorised`).
            (segments.len() >= 3).then_some(segments)
        });
    let Some(segments) = segments else {
        return false;
    };
    let Some((member, owner_segments)) = segments.split_last() else {
        return false;
    };
    let Some(root) = owner_segments.first() else {
        return false;
    };
    if !bindings.is_shadowed(root) {
        return false;
    }
    let Some(binding) = precise_scala_binding(bindings, root) else {
        return true;
    };
    let Some(mut owner) = binding.receiver_type else {
        return true;
    };
    let mut exact_owner = binding.receiver_declaration.or_else(|| {
        let declarations = ctx.types.index.by_fqn(&owner);
        let mut candidates = declarations.iter().filter(|unit| unit.is_class());
        let declaration = candidates.next()?.clone();
        candidates.next().is_none().then_some(declaration)
    });
    for segment in &owner_segments[1..] {
        let resolution = exact_owner.as_ref().map_or_else(
            || {
                ctx.types
                    .field_for_owner_member(ctx.scala, token, &owner, segment)
            },
            |owner| {
                ctx.types
                    .field_for_owner_unit(ctx.scala, token, owner, segment)
            },
        );
        owner = match resolution {
            FieldResolution::Resolved(field) => match field.declared_type {
                Some(declared_type) => {
                    exact_owner = ctx
                        .types
                        .exact_structural_parent(ctx.scala, &field.declaration)
                        .and_then(|context| {
                            match ctx
                                .types
                                .exact_type_declaration_for_owner_context(&declared_type, &context)
                            {
                                ScalaTypeNamespaceResolution::Resolved(declaration) => {
                                    Some(declaration)
                                }
                                ScalaTypeNamespaceResolution::NoMatch
                                | ScalaTypeNamespaceResolution::AuthoritativeMiss
                                | ScalaTypeNamespaceResolution::Ambiguous(_) => None,
                            }
                        });
                    declared_type
                }
                None => return true,
            },
            FieldResolution::NoMatch => {
                let Some(nested_object) = exact_owner.as_ref().and_then(|owner| {
                    ctx.types
                        .exact_nested_object_for_owner(ctx.scala, owner, segment)
                }) else {
                    return true;
                };
                exact_owner = Some(nested_object.clone());
                nested_object.fq_name()
            }
            FieldResolution::Unresolved => return true,
        };
    }
    let resolution = exact_owner.as_ref().map_or_else(
        || {
            ctx.types
                .field_for_owner_member(ctx.scala, token, &owner, member)
        },
        |owner| {
            ctx.types
                .field_for_owner_unit(ctx.scala, token, owner, member)
        },
    );
    match resolution {
        FieldResolution::Resolved(field) => {
            ctx.record_exact(field.declaration, ScalaReferenceRole::Field, node);
        }
        FieldResolution::Unresolved => {}
        FieldResolution::NoMatch => {
            // The terminal segment can name a nested object of the receiver
            // type rather than one of its fields, which is how lagom's `case
            // entity.PersistNone =>` selects the `case object PersistNone` that
            // `entity`'s trait declares. The intermediate loop above and the
            // `field_expression` receiver route already read that member; a
            // `stable_identifier` pattern reaches only this arm, because the
            // parser gives it no `value` field to dispatch a receiver from.
            let object = exact_owner
                .as_ref()
                .and_then(|owner| {
                    ctx.types
                        .exact_nested_object_for_owner(ctx.scala, owner, member)
                })
                .or_else(|| {
                    ctx.types
                        .exact_nested_object_unit(ctx.scala, &owner, member)
                });
            if let Some(object) = object {
                ctx.record_exact(object, ScalaReferenceRole::StableObject, node);
                return true;
            }
            if let Some(exact_owner) = exact_owner.as_ref() {
                if let BareMemberResolution::Resolved(methods) = ctx
                    .types
                    .bare_member_declarations_for_owner(ctx.scala, token, exact_owner, member, None)
                {
                    for method in methods {
                        ctx.record_exact_callable(method, node);
                    }
                }
            } else {
                record_ordinary_class_methods(&owner, token, member, None, node, ctx);
            }
        }
    }
    true
}

/// A receiver root is itself a field reference even when the terminal member
/// is a method call. Record that root before terminal dispatch, preserving a
/// direct field binding across assignment refreshes while failing closed for a
/// local or parameter shadow of the same spelling.
fn record_enclosing_field_qualifier(
    node: Node<'_>,
    token: QueryToken<'_>,
    name: &str,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> bool {
    if !node.parent().is_some_and(|parent| {
        parent.kind() == "field_expression" && parent.child_by_field_name("value") == Some(node)
    }) {
        return false;
    }
    record_lexically_visible_field_reference(node, token, name, ctx, bindings)
        == LexicalFieldReferenceResolution::Consumed
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LexicalFieldReferenceResolution {
    Consumed,
    CallableBound,
    NoMatch,
}

/// Resolve an unqualified field through Scala's exact lexical owner chain.
///
/// Local and parameter bindings are authoritative. Otherwise each physical
/// enclosing template is examined nearest-first, including that template's
/// inherited field tier and the members its self type contributes. A field
/// declaration, field ambiguity, or callable at the nearest matching tier stops
/// the walk, so neither a same-named outer field nor a package-level member can
/// leak through it. Callable recording is left to the existing shape-aware path
/// after this helper reports
/// [`LexicalFieldReferenceResolution::CallableBound`].
fn record_lexically_visible_field_reference(
    node: Node<'_>,
    token: QueryToken<'_>,
    name: &str,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> LexicalFieldReferenceResolution {
    let bound_field_owner = exact_owner_field_binding(bindings, name);
    if bindings.is_shadowed(name) && bound_field_owner.is_none() {
        return LexicalFieldReferenceResolution::Consumed;
    }
    let enclosing_templates = enclosing_template_declarations(node)
        .into_iter()
        .filter_map(|declaration| {
            let owner = ctx
                .class_ranges
                .unit_for_exact_span(declaration.start_byte(), declaration.end_byte())?
                .clone();
            Some((owner, declaration))
        })
        .collect::<Vec<_>>();
    // Scala lets one name carry a `val` and a `def` in one template, and an
    // application selects between them by shape: `images` is the `val` and
    // `images(registry)` is the `def`. The node carries that shape, so a tier
    // that declares a callable the application can reach yields to the
    // shape-aware callable path instead of answering with its field.
    let applied_call_shape = is_call_function_reference(node)
        .then(|| call_site_shape_for_reference(node))
        .flatten();
    let mut owner = ctx.enclosing_class_unit(node.start_byte()).cloned();
    let mut seen = HashSet::default();
    while let Some(current) = owner {
        if !seen.insert(current.clone()) {
            return LexicalFieldReferenceResolution::Consumed;
        }
        owner = ctx.types.exact_structural_parent(ctx.scala, &current);
        if !current.is_class() {
            continue;
        }
        if applied_call_shape.is_some()
            && callable_name_is_bound_for_exact_owner(&current, name, ctx)
        {
            return LexicalFieldReferenceResolution::CallableBound;
        }
        match ctx
            .types
            .field_for_owner_unit(ctx.scala, token, &current, name)
        {
            FieldResolution::Resolved(field) => {
                ctx.record_exact(field.declaration, ScalaReferenceRole::Field, node);
                return LexicalFieldReferenceResolution::Consumed;
            }
            FieldResolution::Unresolved => return LexicalFieldReferenceResolution::Consumed,
            FieldResolution::NoMatch if bound_field_owner.as_ref() == Some(&current) => {
                ctx.record_exact_owner_member(current, name, ScalaReferenceRole::Field, node);
                return LexicalFieldReferenceResolution::Consumed;
            }
            FieldResolution::NoMatch => {}
        }
        if callable_name_is_bound_for_exact_owner(&current, name, ctx) {
            return LexicalFieldReferenceResolution::CallableBound;
        }
        let Some((_, declaration)) = enclosing_templates
            .iter()
            .find(|(template, _)| *template == current)
        else {
            continue;
        };
        match self_type_field_resolution(*declaration, token, name, ctx) {
            FieldResolution::Resolved(field) => {
                ctx.record_exact(field.declaration, ScalaReferenceRole::Field, node);
                return LexicalFieldReferenceResolution::Consumed;
            }
            FieldResolution::Unresolved => return LexicalFieldReferenceResolution::Consumed,
            FieldResolution::NoMatch => {}
        }
    }
    if bound_field_owner.is_some() {
        LexicalFieldReferenceResolution::Consumed
    } else {
        LexicalFieldReferenceResolution::NoMatch
    }
}

/// The field a bare name selects through `declaration`'s self type.
///
/// `trait T { self: A with B => ... }` puts every member of `A` and `B` into
/// scope for `T`'s body, and the corpus uses that cake-pattern shape as the
/// ordinary way to reach a collaborator's `val`. The callable paths already
/// consult `template_self_types`; the field path did not, so a bare read of a
/// self-type `val` produced no edge at all while forward resolution named the
/// declaration.
///
/// Two self types that declare one name leave the reference ambiguous, and an
/// ambiguous owner inside one self type's hierarchy fails closed, exactly as
/// the template's own field tier does. A self type Bifrost does not index
/// contributes nothing rather than blocking the ones it does index.
fn self_type_field_resolution(
    declaration: Node<'_>,
    token: QueryToken<'_>,
    name: &str,
    ctx: &ScalaScan<'_, '_>,
) -> FieldResolution {
    let mut matches = Vec::new();
    for self_type in template_self_types(declaration) {
        let Some(owner) = resolve_receiver_type_declaration_node(self_type, token, ctx) else {
            continue;
        };
        match ctx
            .types
            .field_for_owner_unit(ctx.scala, token, &owner, name)
        {
            FieldResolution::Resolved(field) => matches.push(field),
            FieldResolution::Unresolved => return FieldResolution::Unresolved,
            FieldResolution::NoMatch => {}
        }
    }
    matches.sort_by(|left, right| left.declaration.cmp(&right.declaration));
    matches.dedup_by(|left, right| left.declaration == right.declaration);
    if matches.len() > 1 {
        return FieldResolution::Unresolved;
    }
    matches
        .pop()
        .map_or(FieldResolution::NoMatch, FieldResolution::Resolved)
}

fn companion_method_value_context(
    mut node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> ScalaMethodValueContext {
    if let Some(method_value) = scala_method_value_wrapper(node) {
        node = method_value;
    } else if let Some(generic) = node.parent().filter(|parent| {
        parent.kind() == "generic_function" && parent.child_by_field_name("function") == Some(node)
    }) {
        node = generic;
    }
    if let Some(postfix) = node.parent().filter(|parent| {
        if parent.kind() != "postfix_expression" {
            return false;
        }
        let Some(operator) = scala_postfix_operator_node(*parent) else {
            return false;
        };
        node_text(operator, ctx.source).trim() == "_"
            && scala_postfix_receiver_node(*parent, operator) == Some(node)
    }) {
        node = postfix;
    }
    if let Some(expected_type) = node
        .parent()
        .and_then(|definition| match definition.kind() {
            "val_definition" | "var_definition"
                if definition.child_by_field_name("value") == Some(node) =>
            {
                definition.child_by_field_name("type")
            }
            "function_definition" if definition.child_by_field_name("body") == Some(node) => {
                definition.child_by_field_name("return_type")
            }
            _ => None,
        })
    {
        if expected_type.kind() != "function_type" {
            return ScalaMethodValueContext::Incompatible;
        }
        let Some(parameter_types) = expected_type.child_by_field_name("parameter_types") else {
            return ScalaMethodValueContext::Incompatible;
        };
        let mut cursor = parameter_types.walk();
        return ScalaMethodValueContext::Function(ScalaFunctionParameterShape::arity_only(
            parameter_types.named_children(&mut cursor).count(),
        ));
    }
    call_parameter_method_value_context(node, token, ctx, bindings)
}

fn call_parameter_method_value_context(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> ScalaMethodValueContext {
    let Some(arguments) = node.parent() else {
        return ScalaMethodValueContext::Unknown;
    };
    if arguments.kind() != "arguments" {
        return ScalaMethodValueContext::Unknown;
    }
    let mut arguments_cursor = arguments.walk();
    let Some(parameter_index) = arguments
        .named_children(&mut arguments_cursor)
        .filter(|argument| is_semantic_call_argument(*argument))
        .position(|argument| argument == node)
    else {
        return ScalaMethodValueContext::Unknown;
    };
    let Some(call) = arguments.parent() else {
        return ScalaMethodValueContext::Unknown;
    };
    if call.kind() != "call_expression" || call.child_by_field_name("arguments") != Some(arguments)
    {
        return ScalaMethodValueContext::Unknown;
    }

    let mut parameter_list = 0usize;
    let Some(mut function) = call.child_by_field_name("function") else {
        return ScalaMethodValueContext::Unknown;
    };
    while function.kind() == "call_expression" {
        parameter_list += 1;
        let Some(inner) = function.child_by_field_name("function") else {
            return ScalaMethodValueContext::Unknown;
        };
        function = inner;
    }
    if function.kind() == "generic_function" {
        let Some(inner) = function.child_by_field_name("function") else {
            return ScalaMethodValueContext::Unknown;
        };
        function = inner;
    }
    let Some(call_arities) = call_arities_for_reference(function) else {
        return ScalaMethodValueContext::Unknown;
    };
    let methods = match function.kind() {
        "identifier" | "operator_identifier" => {
            let function_name = node_text(function, ctx.source).trim();
            if function_name.is_empty() {
                return ScalaMethodValueContext::Unknown;
            }
            if bindings.is_shadowed(function_name) {
                return ScalaMethodValueContext::Incompatible;
            }
            let Some(owner) = ctx.enclosing_class_unit(function.start_byte()) else {
                return ScalaMethodValueContext::Unknown;
            };
            match ctx.types.bare_member_declarations_for_owner(
                ctx.scala,
                token,
                owner,
                function_name,
                Some(&call_arities),
            ) {
                BareMemberResolution::Resolved(methods) => methods,
                BareMemberResolution::NoMatch => {
                    let Some(imported) = ctx.resolver.resolve_member(function_name) else {
                        return ScalaMethodValueContext::Unknown;
                    };
                    ctx.types
                        .definitions(&imported)
                        .into_iter()
                        .filter(CodeUnit::is_function)
                        .collect()
                }
                BareMemberResolution::Unresolved => return ScalaMethodValueContext::Incompatible,
            }
        }
        "field_expression" => {
            let (Some(receiver), Some(field)) = (
                function.child_by_field_name("value"),
                function.child_by_field_name("field"),
            ) else {
                return ScalaMethodValueContext::Unknown;
            };
            let function_name = node_text(field, ctx.source).trim();
            if function_name.is_empty() {
                return ScalaMethodValueContext::Unknown;
            }
            let Some(owner) = receiver_value_owner(receiver, token, ctx, bindings) else {
                return ScalaMethodValueContext::Unknown;
            };
            match match &owner {
                ScalaValueOwner::Exact(owner) => {
                    ctx.types.effective_method_declarations_for_exact_owner(
                        ctx.scala,
                        token,
                        owner,
                        function_name,
                        Some(&call_arities),
                    )
                }
                ScalaValueOwner::Logical(owner) => {
                    ctx.types.effective_method_declarations_for_owner(
                        ctx.scala,
                        token,
                        owner,
                        function_name,
                        Some(&call_arities),
                    )
                }
            } {
                BareMemberResolution::Resolved(methods) => methods,
                BareMemberResolution::NoMatch => return ScalaMethodValueContext::Unknown,
                BareMemberResolution::Unresolved => return ScalaMethodValueContext::Incompatible,
            }
        }
        _ => return ScalaMethodValueContext::Unknown,
    };
    if methods.is_empty() {
        return ScalaMethodValueContext::Incompatible;
    }

    let mut resolved = None;
    for method in methods {
        let Some(shape) = ctx.types.callable_parameter_function_shape(
            ctx.scala,
            token,
            &method,
            &call_arities,
            parameter_list,
            parameter_index,
        ) else {
            return ScalaMethodValueContext::Incompatible;
        };
        if resolved.as_ref().is_some_and(|resolved| resolved != &shape) {
            return ScalaMethodValueContext::Incompatible;
        }
        resolved = Some(shape);
    }
    resolved.map_or(
        ScalaMethodValueContext::Incompatible,
        ScalaMethodValueContext::Function,
    )
}

fn record_ordinary_class_methods(
    owner_fq_name: &str,
    token: QueryToken<'_>,
    member: &str,
    call_arities: Option<&[usize]>,
    node: Node<'_>,
    ctx: &mut ScalaScan<'_, '_>,
) -> bool {
    let owner_declarations = ctx.types.index.by_fqn(owner_fq_name);
    let mut owners = owner_declarations.iter().filter(|owner| {
        ctx.types
            .owner_supports_ordinary_member_lookup(ctx.scala, owner)
    });
    let Some(owner) = owners.next() else {
        return false;
    };
    if owners.next().is_some() {
        return true;
    }
    match ctx.types.effective_method_declarations_for_exact_owner(
        ctx.scala,
        token,
        owner,
        member,
        call_arities,
    ) {
        BareMemberResolution::Resolved(methods) => {
            for method in methods {
                record_exact_callable_reference(method, node, ctx);
            }
            true
        }
        BareMemberResolution::Unresolved => true,
        BareMemberResolution::NoMatch => false,
    }
}

fn record_exact_callable_reference(method: CodeUnit, node: Node<'_>, ctx: &mut ScalaScan<'_, '_>) {
    if is_explicit_eta_reference(node, ctx.source) || is_unapplied_type_application(node) {
        ctx.record_exact(method, ScalaReferenceRole::Callable, node);
    } else {
        ctx.record_exact_callable(method, node);
    }
}

/// `m[T]` with no argument list. Scala reads it as a parameterless call when
/// `m` declares no parameters and as an eta-expanded method value when it does,
/// so the reference carries no call shape: claiming the empty argument list the
/// call-site shape invents for a type application would reject every method
/// that takes parameters, which is what `_.map(fromEncodeable[T])` writes.
fn is_unapplied_type_application(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "generic_function"
            && parent.child_by_field_name("function") == Some(node)
            && !is_call_function_reference(node)
    })
}

fn is_explicit_eta_reference(mut node: Node<'_>, source: &str) -> bool {
    if scala_method_value_wrapper(node).is_some() {
        return true;
    }
    if let Some(generic) = node.parent().filter(|parent| {
        parent.kind() == "generic_function" && parent.child_by_field_name("function") == Some(node)
    }) {
        node = generic;
    }
    let Some(postfix) = node
        .parent()
        .filter(|parent| parent.kind() == "postfix_expression")
    else {
        return false;
    };
    let Some(operator) = scala_postfix_operator_node(postfix) else {
        return false;
    };
    node_text(operator, source).trim() == "_"
        && scala_postfix_receiver_node(postfix, operator) == Some(node)
}

/// The released grammar represents `method _` as `method_value`, while older
/// grammars use a postfix expression. Preserve the whole value node so callers
/// can read its expected function type from the surrounding context.
fn scala_method_value_wrapper(mut node: Node<'_>) -> Option<Node<'_>> {
    if let Some(generic) = node.parent().filter(|parent| {
        parent.kind() == "generic_function" && parent.child_by_field_name("function") == Some(node)
    }) {
        node = generic;
    }
    node.parent()
        .filter(|parent| parent.kind() == "method_value")
}

fn record_lexically_visible_call(
    node: Node<'_>,
    token: QueryToken<'_>,
    member: &str,
    call_shape: &ScalaCallSiteShape,
    ctx: &mut ScalaScan<'_, '_>,
) -> bool {
    let call_arities = call_shape
        .lists
        .iter()
        .map(|list| list.arity)
        .collect::<Vec<_>>();
    let fallback_arities =
        (call_shape.method_value_arity.is_none()).then_some(call_arities.as_slice());
    for declaration in enclosing_template_declarations(node) {
        if let Some(owner) = ctx
            .class_ranges
            .unit_for_exact_span(declaration.start_byte(), declaration.end_byte())
        {
            let resolution = ctx
                .types
                .effective_method_declarations_for_exact_owner_with_shape(
                    ctx.scala, token, owner, member, call_shape,
                );
            match resolution {
                BareMemberResolution::Resolved(methods) => {
                    for method in methods {
                        ctx.record_exact_callable_with_shape(method, node, call_shape);
                    }
                    return true;
                }
                BareMemberResolution::Unresolved => return true,
                BareMemberResolution::NoMatch => {
                    let expected_type_is_unresolved = call_shape
                        .method_value_parameter_types
                        .as_ref()
                        .is_some_and(|types| {
                            types.iter().any(|identity| {
                                matches!(identity, ScalaParameterTypeIdentity::Unresolved(_))
                            })
                        });
                    if (call_shape.method_value_parameter_types_authoritative
                        || expected_type_is_unresolved)
                        && callable_name_is_bound_for_exact_owner(owner, member, ctx)
                    {
                        return true;
                    }
                }
            }
        }
        match ordinary_class_member_declarations_for_template(
            declaration,
            token,
            member,
            fallback_arities,
            ctx,
        ) {
            BareMemberResolution::Resolved(methods) => {
                for method in methods {
                    ctx.record_exact_callable_with_shape(method, node, call_shape);
                }
                return true;
            }
            BareMemberResolution::Unresolved => return true,
            BareMemberResolution::NoMatch => {}
        }
        for self_type in template_self_types(declaration) {
            if let Some(self_owner) = resolve_receiver_type_node(self_type, token, ctx)
                && record_ordinary_class_methods(
                    &self_owner,
                    token,
                    member,
                    fallback_arities,
                    node,
                    ctx,
                )
            {
                return true;
            }
        }
    }
    false
}

fn callable_name_is_bound_for_exact_owner(
    owner: &CodeUnit,
    member: &str,
    ctx: &ScalaScan<'_, '_>,
) -> bool {
    ctx.types
        .linearized_owners(ctx.scala, owner)
        .iter()
        .any(|owner| {
            ctx.types
                .members_for_exact_owner_unit(ctx.scala, owner, member)
                .iter()
                .any(|unit| {
                    unit.is_function()
                        && ctx.types.fallback_callable_role(ctx.scala, unit)
                            == ScalaCallableRole::Ordinary
                })
        })
}

fn record_lexically_visible_parameterless_method(
    node: Node<'_>,
    token: QueryToken<'_>,
    member: &str,
    ctx: &mut ScalaScan<'_, '_>,
) -> bool {
    if ctx
        .lexically_visible_object(node.start_byte(), member)
        .is_some()
    {
        return false;
    }
    if record_extension_scope_parameterless_method(node, token, member, ctx) {
        return true;
    }
    for declaration in enclosing_template_declarations(node) {
        if let Some(owner) = ctx
            .class_ranges
            .unit_for_exact_span(declaration.start_byte(), declaration.end_byte())
        {
            match ctx.types.effective_method_declarations_for_exact_owner(
                ctx.scala, token, owner, member, None,
            ) {
                BareMemberResolution::Resolved(methods) => {
                    for method in methods {
                        record_exact_callable_reference(method, node, ctx);
                    }
                    return true;
                }
                BareMemberResolution::Unresolved => return true,
                BareMemberResolution::NoMatch => {}
            }
        }
        match ordinary_class_member_declarations_for_template(declaration, token, member, None, ctx)
        {
            BareMemberResolution::Resolved(methods) => {
                for method in methods {
                    record_exact_callable_reference(method, node, ctx);
                }
                return true;
            }
            BareMemberResolution::Unresolved => return true,
            BareMemberResolution::NoMatch => {}
        }
        for self_type in template_self_types(declaration) {
            if let Some(self_owner) = resolve_receiver_type_node(self_type, token, ctx)
                && record_ordinary_class_methods(&self_owner, token, member, None, node, ctx)
            {
                return true;
            }
        }
    }
    false
}

fn record_extension_scope_parameterless_method(
    node: Node<'_>,
    token: QueryToken<'_>,
    member: &str,
    ctx: &mut ScalaScan<'_, '_>,
) -> bool {
    for extension in enclosing_extension_definitions(node) {
        let Some(receiver_type) =
            scala_extension_receiver_type_node_local(extension.child_by_field_name("parameters"))
        else {
            continue;
        };
        let Some(receiver_owner) = resolve_receiver_type_node(receiver_type, token, ctx) else {
            return true;
        };
        let mut methods = ctx
            .types
            .index
            .identifier(member)
            .iter()
            .filter(|declaration| {
                declaration.is_function() && declaration.source() == ctx.source_file
            })
            .filter_map(|declaration| {
                ctx.types
                    .extension_method_for_unit(ctx.scala, token, declaration)
            })
            .filter(|method| declaration_within_node(ctx, &method.declaration, extension))
            .collect::<Vec<_>>();
        methods.sort_by(|left, right| left.declaration.cmp(&right.declaration));
        methods.dedup_by(|left, right| left.declaration == right.declaration);
        let callable_count = methods
            .iter()
            .flat_map(|method| method.alternatives.iter())
            .filter(|alternative| {
                alternative.role == ScalaCallableRole::Ordinary
                    && extension_alternative_receiver_matches(
                        &ctx.resolver,
                        alternative,
                        Some(&receiver_owner),
                    )
            })
            .count();
        let unique_callable = callable_count == 1;
        methods.retain(|method| {
            method.alternatives.iter().any(|alternative| {
                alternative.role == ScalaCallableRole::Ordinary
                    && extension_alternative_receiver_matches(
                        &ctx.resolver,
                        alternative,
                        Some(&receiver_owner),
                    )
                    && ordinary_callable_shape_matches(alternative, None, unique_callable)
            })
        });
        match methods.as_slice() {
            [] => {}
            [method] => {
                ctx.record_exact(
                    method.declaration.clone(),
                    ScalaReferenceRole::Callable,
                    node,
                );
                return true;
            }
            _ => return true,
        }
    }
    false
}

fn enclosing_extension_definitions(mut node: Node<'_>) -> Vec<Node<'_>> {
    let mut definitions = Vec::new();
    while let Some(parent) = node.parent() {
        if parent.kind() == "extension_definition" {
            definitions.push(parent);
        }
        node = parent;
    }
    definitions
}

fn scala_extension_receiver_type_node_local(
    receiver_parameters: Option<Node<'_>>,
) -> Option<Node<'_>> {
    let receiver_parameters = receiver_parameters?;
    let mut cursor = receiver_parameters.walk();
    let mut receivers = receiver_parameters
        .named_children(&mut cursor)
        .filter(|parameter| matches!(parameter.kind(), "parameter" | "class_parameter"));
    let receiver = receivers.next()?;
    if receivers.next().is_some() {
        return None;
    }
    receiver.child_by_field_name("type")
}

fn declaration_within_node(
    ctx: &ScalaScan<'_, '_>,
    declaration: &CodeUnit,
    node: Node<'_>,
) -> bool {
    ctx.scala
        .ranges(declaration)
        .iter()
        .any(|range| range.start_byte >= node.start_byte() && range.end_byte <= node.end_byte())
}

fn ordinary_class_member_declarations_for_template(
    declaration: Node<'_>,
    token: QueryToken<'_>,
    member: &str,
    call_arities: Option<&[usize]>,
    ctx: &ScalaScan<'_, '_>,
) -> BareMemberResolution {
    if let Some(owner) = ctx
        .class_ranges
        .unit_for_exact_span(declaration.start_byte(), declaration.end_byte())
    {
        return ctx.types.ordinary_class_member_declarations_for_owner(
            ctx.scala,
            token,
            owner,
            member,
            call_arities,
        );
    }
    if template_direct_term_member_named(declaration, member, ctx.source) {
        return BareMemberResolution::Unresolved;
    }
    let Some(owners) = template_supertype_owners(declaration, token, ctx) else {
        return BareMemberResolution::Unresolved;
    };
    if owners.is_empty() {
        BareMemberResolution::NoMatch
    } else {
        ctx.types.ordinary_class_member_declarations_for_owners(
            ctx.scala,
            token,
            &owners,
            member,
            call_arities,
        )
    }
}

fn template_supertype_owners(
    declaration: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
) -> Option<Vec<CodeUnit>> {
    let mut owners = Vec::new();
    for (_, lookup_node) in scala_supertype_lookup_nodes(declaration) {
        let fqn = resolve_receiver_type_node(lookup_node, token, ctx)?;
        let candidates = ctx.types.index.by_fqn(&fqn);
        let mut declarations = candidates.iter().filter(|unit| unit.is_class());
        let owner = declarations.next()?;
        if declarations.next().is_some() {
            return None;
        }
        owners.push(owner.clone());
    }
    Some(owners)
}

/// The fqn of a receiver expression's type, for the shapes that resolve without
/// return-type inference.
fn receiver_type_declaration(
    receiver: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> Option<CodeUnit> {
    match receiver.kind() {
        "identifier" => {
            let name = node_text(receiver, ctx.source);
            if name == "this" {
                return ctx.enclosing_class_unit(receiver.start_byte()).cloned();
            }
            if let Some(binding) = precise_scala_binding(bindings, name) {
                if let Some(declaration) = binding.receiver_declaration {
                    return Some(declaration);
                }
                let receiver_type = binding.receiver_type?;
                return exact_receiver_type_declaration(
                    &receiver_type,
                    ctx.enclosing_class_unit(receiver.start_byte())?,
                    ctx,
                );
            }
            if bindings.is_shadowed(name) || !is_field_expression_value(receiver) {
                return None;
            }
            match ctx.visible_object_reference(receiver.start_byte(), name) {
                Some(ScalaResolvedReference::Exact(object)) => Some(object),
                Some(ScalaResolvedReference::Logical(_)) | None => None,
            }
        }
        "field_expression" => {
            let value = receiver.child_by_field_name("value")?;
            let member = receiver.child_by_field_name("field")?;
            let Some(owner) = receiver_type_declaration(value, token, ctx, bindings) else {
                return stable_object_path_declaration(receiver, ctx, bindings);
            };
            let member = node_text(member, ctx.source).trim();
            match ctx
                .types
                .field_for_owner_unit(ctx.scala, token, &owner, member)
            {
                FieldResolution::Resolved(field) => {
                    let declared_type = field.declared_type?;
                    let owner_context = ctx
                        .scala
                        .structural_parent_of(&field.declaration)
                        .unwrap_or(owner);
                    return exact_receiver_type_declaration(&declared_type, &owner_context, ctx);
                }
                FieldResolution::Unresolved => return None,
                FieldResolution::NoMatch => {}
            }
            match ctx.types.unqualified_member_return_type(
                ctx.scala,
                token,
                &ctx.resolver,
                &owner,
                member,
                None,
            ) {
                MemberReturnResolution::Resolved(declared_type) => {
                    exact_receiver_type_declaration(&declared_type, &owner, ctx)
                }
                MemberReturnResolution::NoMatch | MemberReturnResolution::Unresolved => None,
            }
        }
        _ => None,
    }
}

/// The semantic owner of a receiver expression.
///
/// Keep a physically resolved declaration as a `CodeUnit` for downstream
/// structural-member queries. Only retain a rendered name when the resolver
/// genuinely cannot prove one declaration. This prevents callers from
/// resolving the receiver once to text and then repeating the same lookup to
/// recover the structured identity they already needed.
fn receiver_value_owner(
    receiver: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> Option<ScalaValueOwner> {
    receiver_type_declaration(receiver, token, ctx, bindings)
        .map(ScalaValueOwner::Exact)
        .or_else(|| receiver_type_fqn(receiver, token, ctx, bindings).map(ScalaValueOwner::Logical))
}

fn exact_receiver_type_declaration(
    receiver_type: &str,
    owner_context: &CodeUnit,
    ctx: &ScalaScan<'_, '_>,
) -> Option<CodeUnit> {
    match ctx
        .types
        .exact_type_declaration_for_owner_context(receiver_type, owner_context)
    {
        ScalaTypeNamespaceResolution::Resolved(declaration) => return Some(declaration),
        ScalaTypeNamespaceResolution::NoMatch
        | ScalaTypeNamespaceResolution::AuthoritativeMiss
        | ScalaTypeNamespaceResolution::Ambiguous(_) => {}
    }
    let declarations = ctx.types.index.by_fqn(receiver_type);
    let mut candidates = declarations.iter().filter(|unit| unit.is_class());
    let declaration = candidates.next()?.clone();
    candidates.next().is_none().then_some(declaration)
}

fn receiver_type_fqn(
    receiver: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> Option<String> {
    match receiver.kind() {
        // `this` is a plain `identifier` in tree-sitter-scala (not its own node).
        "identifier" => {
            let name = node_text(receiver, ctx.source);
            if name == "this" {
                return ctx
                    .enclosing_class(receiver.start_byte())
                    .map(str::to_string);
            }
            // A typed local resolves to its type; otherwise the name may be an
            // object/type, unless it is a known (shadowed) untyped local.
            precise_scala_binding(bindings, name)
                .and_then(|binding| binding.receiver_type)
                .or_else(|| {
                    if bindings.is_shadowed(name) {
                        return None;
                    }
                    let owner = ctx.enclosing_class_unit(receiver.start_byte())?;
                    match ctx
                        .types
                        .field_for_owner_unit(ctx.scala, token, owner, name)
                    {
                        FieldResolution::Resolved(field) => field.declared_type,
                        FieldResolution::NoMatch | FieldResolution::Unresolved => None,
                    }
                })
                .or_else(|| {
                    (!bindings.is_shadowed(name) && is_field_expression_value(receiver)).then(
                        || {
                            ctx.visible_object_reference(receiver.start_byte(), name)
                                .map(|reference| match reference {
                                    ScalaResolvedReference::Exact(object) => object.fq_name(),
                                    ScalaResolvedReference::Logical(fqn) => fqn,
                                })
                        },
                    )?
                })
                .or_else(|| {
                    (!bindings.is_shadowed(name)).then(|| {
                        ctx.resolver.resolve_member(name).and_then(|method| {
                            ctx.types
                                .member_return_type(ctx.scala, token, &ctx.resolver, &method)
                        })
                    })?
                })
                .or_else(|| {
                    (!bindings.is_shadowed(name)).then(|| {
                        ctx.resolver
                            .resolve_object(name)
                            .or_else(|| ctx.resolver.resolve(name))
                    })?
                })
        }
        "field_expression" if is_owner_qualified_this(receiver, ctx.source) => {
            let owner = receiver.child_by_field_name("value")?;
            let name = node_text(owner, ctx.source).trim();
            ctx.visible_type(token, owner, name)
        }
        "field_expression" => stable_object_expression_fqn(receiver, ctx, bindings).or_else(|| {
            let value = receiver.child_by_field_name("value")?;
            let field = receiver.child_by_field_name("field")?;
            let owner = receiver_value_owner(value, token, ctx, bindings)?;
            let member = node_text(field, ctx.source).trim();
            if member.is_empty() {
                return None;
            }
            let resolution = match &owner {
                ScalaValueOwner::Exact(owner) => ctx
                    .types
                    .field_for_owner_unit(ctx.scala, token, owner, member),
                ScalaValueOwner::Logical(owner) => ctx
                    .types
                    .field_for_owner_member(ctx.scala, token, owner, member),
            };
            match resolution {
                FieldResolution::Resolved(field) => field.declared_type,
                FieldResolution::NoMatch | FieldResolution::Unresolved => None,
            }
        }),
        "instance_expression" => constructed_type(receiver, token, ctx),
        "call_expression" => call_result_type(receiver, token, ctx, bindings),
        kind => scala_literal_type_name(kind).map(|name| {
            let scala_fqn = format!("scala.{name}");
            let declarations = ctx.types.index.by_fqn(&scala_fqn);
            if declarations.len() == 1 && declarations[0].is_class() {
                scala_fqn
            } else {
                name.to_string()
            }
        }),
    }
}

fn stable_object_expression_fqn(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> Option<String> {
    resolve_stable_object_expression(
        node,
        ctx.source,
        |root| {
            (bindings.resolve_symbol(root).is_unknown() && !bindings.is_shadowed(root))
                .then(|| ctx.resolver.resolve_object(root))
                .flatten()
        },
        |owner, member| ctx.types.exact_nested_object(ctx.scala, owner, member),
    )
    .or_else(|| stable_object_path_declaration(node, ctx, bindings).map(|object| object.fq_name()))
}

/// The object a dotted receiver path names when its root is a package rather
/// than a term the object-name resolver already binds.
///
/// `stable_object_expression_fqn` starts from an imported or lexically visible
/// object and then selects nested objects. A path rooted at a package --
/// `com.example.transport.Method` written out, or `transport.Method` after
/// `import com.example.transport` -- has no such root, so the receiver stayed
/// untyped and every selection off it went unrecorded. The qualified stable
/// resolver already understands package roots, `_root_`, imported packages and
/// nested objects, so read the path through it. A local binding of the root
/// spelling shadows the package and keeps the path out of this rule.
fn stable_object_path_declaration(
    receiver: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> Option<CodeUnit> {
    let segments = stable_path_segments(receiver, ctx.source)?;
    let root = segments.first().expect("a stable path has a root segment");
    if !bindings.resolve_symbol(root).is_unknown() || bindings.is_shadowed(root) {
        return None;
    }
    let lexical_root = ctx.lexically_visible_object_unit(receiver.start_byte(), root);
    ctx.types.resolve_qualified_stable_type_unit_at(
        ctx.scala,
        &ctx.resolver,
        &segments,
        true,
        lexical_root,
    )
}

fn seed_declaration(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    match node.kind() {
        "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
            seed_class_parameters(node, token, ctx, bindings);
            preseed_direct_owner_fields(node, token, ctx, bindings);
        }
        "extension_definition" => seed_parameters(node, token, ctx, bindings),
        "function_definition" => {
            // #1854: a method's own name is NOT a local binding inside its own
            // body. Declaring it here made every bare `name(..)` inside
            // `def name(..)` opaque, so recursion and same-name overload
            // siblings were dropped before any owner, import, or overload
            // lookup. A genuinely nested `def` still shadows, because
            // `seed_parent_scope_declaration` declares it in the ENCLOSING
            // scope, where the shadow belongs.
            preseed_enclosing_owner_fields(node, token, ctx, bindings);
            if let Some(extension) = node
                .parent()
                .filter(|parent| parent.kind() == "extension_definition")
            {
                // An extension receiver is an implicit parameter of every
                // directly enclosed method. It therefore wins over a method
                // with the same term name inside that method's body.
                seed_parameters(extension, token, ctx, bindings);
            }
            seed_parameters(node, token, ctx, bindings);
        }
        "val_definition" | "var_definition" => seed_value_definition(node, token, ctx, bindings),
        _ => {}
    }
}

fn preseed_enclosing_owner_fields(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        match ancestor.kind() {
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
                preseed_direct_owner_fields(ancestor, token, ctx, bindings);
                return;
            }
            "function_definition"
            | "block"
            | "block_expression"
            | "case_clause"
            | "lambda_expression"
            | "anonymous_function" => return,
            _ => current = ancestor.parent(),
        }
    }
}

fn refresh_assignment_binding(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };
    if !matches!(left.kind(), "identifier" | "operator_identifier") {
        return;
    }
    let name = node_text(left, ctx.source).trim();
    if name.is_empty() || !bindings.is_shadowed(name) {
        return;
    }
    let declaration_owner =
        precise_scala_binding(bindings, name).and_then(|binding| binding.declaration_owner);
    let source_binding = matches!(right.kind(), "identifier" | "operator_identifier")
        .then(|| precise_scala_binding(bindings, node_text(right, ctx.source).trim()))
        .flatten();
    if let Some(receiver_declaration) = source_binding
        .as_ref()
        .and_then(|binding| binding.receiver_declaration.clone())
    {
        seed_scala_binding_with_receiver_declaration(
            name,
            receiver_declaration,
            declaration_owner,
            bindings,
        );
        return;
    }
    let receiver = constructed_or_applied_type(right, token, ctx)
        .or_else(|| call_result_type(right, token, ctx, bindings).map(ScalaValueOwner::Logical))
        .or_else(|| {
            source_binding
                .and_then(|binding| binding.receiver_type)
                .map(ScalaValueOwner::Logical)
        });
    seed_value_owner(
        name,
        receiver.and_then(|owner| exactify_value_owner(owner, left.start_byte(), ctx)),
        declaration_owner,
        bindings,
    );
}

fn record_override_declaration(node: Node<'_>, ctx: &mut ScalaScan<'_, '_>) {
    if !matches!(node.kind(), "function_definition" | "function_declaration") {
        return;
    }
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    if !node
        .parent()
        .is_some_and(|parent| matches!(parent.kind(), "template_body" | "enum_body"))
    {
        return;
    }
    let name = node_text(name_node, ctx.source).trim();
    if name.is_empty() || !ctx.sink.may_match_name(name) {
        return;
    }
    let Some(owner) = ctx.enclosing_class(name_node.start_byte()) else {
        return;
    };
    let method_fqn = format!("{owner}.{name}");
    let targets = ctx.types.override_targets_for_method(
        ctx.scala,
        ctx.token,
        owner,
        &method_fqn,
        name,
        function_definition_arity(node, ctx.source),
    );
    for target in targets.iter().cloned() {
        ctx.record_with_caller(method_fqn.clone(), target, name_node);
    }
}

fn function_definition_arity(node: Node<'_>, source: &str) -> Option<usize> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == "parameters")
        .and_then(|parameters| parenthesized_arity(node_text(parameters, source)))
        .or(Some(0))
}

fn seed_parameters(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "parameters" {
            continue;
        }
        let mut inner = child.walk();
        for parameter in child.named_children(&mut inner) {
            if parameter.kind() == "parameter" {
                seed_parameter(parameter, token, ctx, None, bindings);
            }
        }
    }
}

fn seed_class_parameters(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    let owner = ctx.enclosing_class_unit(node.start_byte()).cloned();
    let mut cursor = node.walk();
    for parameters in node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "class_parameters")
    {
        let mut parameter_cursor = parameters.walk();
        for parameter in parameters.named_children(&mut parameter_cursor) {
            if parameter.kind() == "class_parameter" {
                let declaration_owner = scala_class_parameter_field_keyword(parameter)
                    .is_some()
                    .then(|| owner.clone())
                    .flatten();
                seed_parameter(parameter, token, ctx, declaration_owner, bindings);
            }
        }
    }
}

fn seed_parameter(
    parameter: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
    declaration_owner: Option<CodeUnit>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    let Some(name) = parameter.child_by_field_name("name") else {
        return;
    };
    let binding_name = node_text(name, ctx.source).trim();
    if binding_name.is_empty() {
        return;
    }
    if let Some(type_node) = parameter.child_by_field_name("type")
        && let Some(paths) = scala_union_type_alternative_paths(type_node, ctx.source)
    {
        let owners = paths
            .iter()
            .map(|path| {
                ctx.types
                    .resolve_type_in_declaration_context(ctx.scala, &ctx.resolver, path)
            })
            .collect::<Option<Vec<_>>>();
        if let Some(owners) = owners {
            bindings.seed_symbol_many(
                binding_name.to_string(),
                owners.into_iter().map(|receiver_type| ScalaLocalBinding {
                    receiver_type: Some(receiver_type),
                    receiver_declaration: None,
                    declaration_owner: declaration_owner.clone(),
                }),
            );
        } else {
            bindings.declare_shadow(binding_name.to_string());
        }
        return;
    }
    if let Some(receiver_declaration) = parameter
        .child_by_field_name("type")
        .and_then(|type_node| resolve_receiver_type_declaration_node(type_node, token, ctx))
    {
        seed_scala_binding_with_receiver_declaration(
            binding_name,
            receiver_declaration,
            declaration_owner,
            bindings,
        );
        return;
    }
    let resolved = parameter
        .child_by_field_name("type")
        .and_then(|type_node| resolve_receiver_type_node(type_node, token, ctx))
        .or_else(|| {
            parameter
                .child_by_field_name("type")
                .and_then(|type_node| resolve_foreign_receiver_type_node(type_node, ctx))
        });
    seed_binding(binding_name, resolved, declaration_owner, bindings);
}

fn preseed_direct_owner_fields(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    let Some(owner) = ctx.enclosing_class_unit(node.start_byte()).cloned() else {
        return;
    };
    let mut cursor = node.walk();
    for body in node
        .named_children(&mut cursor)
        .filter(|child| matches!(child.kind(), "template_body" | "enum_body"))
    {
        preseed_owner_fields_in(body, token, ctx, &owner, bindings);
    }
}

fn preseed_owner_fields_in(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
    owner: &CodeUnit,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "val_definition" | "var_definition" => {
                if direct_owner_field_owner(child, ctx).as_ref() == Some(owner) {
                    seed_value_definition_with_owner(
                        child,
                        token,
                        ctx,
                        Some(owner.clone()),
                        bindings,
                    );
                }
            }
            "function_definition"
            | "function_declaration"
            | "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition"
            | "block"
            | "block_expression"
            | "indented_block"
            | "case_clause"
            | "lambda_expression"
            | "anonymous_function" => {}
            _ => preseed_owner_fields_in(child, token, ctx, owner, bindings),
        }
    }
}

fn seed_value_definition(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    let declaration_owner = direct_owner_field_owner(node, ctx);
    seed_value_definition_with_owner(node, token, ctx, declaration_owner, bindings);
}

fn seed_value_definition_with_owner(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
    declaration_owner: Option<CodeUnit>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    // Prefer the declared type; otherwise infer from a `new Foo()` initializer
    // or a call with a declared factory return. A declared type with no Scala
    // declaration still binds when the realm proves it foreign (#1859).
    let receiver_declaration = node
        .child_by_field_name("type")
        .and_then(|type_node| resolve_receiver_type_declaration_node(type_node, token, ctx));
    let resolved = node
        .child_by_field_name("type")
        .filter(|_| receiver_declaration.is_none())
        .and_then(|type_node| {
            resolve_receiver_type_node(type_node, token, ctx)
                .or_else(|| resolve_foreign_receiver_type_node(type_node, ctx))
        })
        .map(ScalaValueOwner::Logical)
        .or_else(|| {
            node.child_by_field_name("value")
                .and_then(|value| constructed_or_applied_type(value, token, ctx))
        })
        .or_else(|| {
            node.child_by_field_name("value")
                .and_then(|value| call_result_type(value, token, ctx, bindings))
                .map(ScalaValueOwner::Logical)
        });
    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    for name in scala_definition_binder_names(pattern, ctx.source) {
        if let Some(receiver_declaration) = receiver_declaration.clone() {
            seed_scala_binding_with_receiver_declaration(
                name,
                receiver_declaration,
                declaration_owner.clone(),
                bindings,
            );
        } else {
            seed_value_owner(
                name,
                resolved
                    .clone()
                    .and_then(|owner| exactify_value_owner(owner, pattern.start_byte(), ctx)),
                declaration_owner.clone(),
                bindings,
            );
        }
    }
}

fn direct_owner_field_owner(node: Node<'_>, ctx: &ScalaScan<'_, '_>) -> Option<CodeUnit> {
    let owner = ctx.enclosing_class_unit(node.start_byte())?.clone();
    let mut current = node.parent();
    while let Some(ancestor) = current {
        match ancestor.kind() {
            "template_body" | "enum_body" => return Some(owner),
            "function_definition"
            | "block"
            | "block_expression"
            | "indented_block"
            | "case_clause"
            | "lambda_expression"
            | "anonymous_function"
            | "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition" => return None,
            _ => current = ancestor.parent(),
        }
    }
    None
}

fn scala_named_template_owner(mut template: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = template.parent() {
        match parent.kind() {
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
                return Some(parent);
            }
            "instance_expression" | "template_body" => return None,
            _ => template = parent,
        }
    }
    None
}

/// The fqn of the type constructed by a `new Foo()` value expression.
fn constructed_type(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
) -> Option<String> {
    constructed_type_declaration(node, token, ctx).map(|target| target.fq_name())
}

/// The exact declaration constructed by a `new Foo()` value expression.
fn constructed_type_declaration(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
) -> Option<CodeUnit> {
    let type_node = constructed_type_node(node)?;
    let path = scala_type_lookup_segments(type_node, ctx.source);
    let name = path.last()?;
    if let Some(target) = resolve_receiver_type_declaration_node(type_node, token, ctx) {
        return exact_constructed_type_target(type_node, token, target, name, ctx);
    }
    let class_fqn = resolve_receiver_type_node(type_node, token, ctx)?;
    ctx.types
        .resolve_type_application(
            ctx.scala,
            token,
            &ctx.resolver,
            Some(&class_fqn),
            None,
            name,
            call_site_shape_for_reference(type_node).as_ref(),
            TypeApplicationRole::ExplicitConstructor,
            Some(ctx.source_file),
        )
        .type_target
}

fn constructed_type_node(mut node: Node<'_>) -> Option<Node<'_>> {
    while node.kind() == "call_expression" {
        node = node.child_by_field_name("function")?;
    }
    if node.kind() != "instance_expression" {
        return None;
    }
    let mut cursor = node.walk();
    let type_nodes = node
        .named_children(&mut cursor)
        .filter(|child| !matches!(child.kind(), "arguments" | "template_body"))
        .collect::<Vec<_>>();
    let [type_node] = type_nodes.as_slice() else {
        return None;
    };
    if matches!(
        type_node.kind(),
        "compound_type" | "infix_type" | "intersection_type" | "with_type"
    ) {
        return None;
    }
    Some(*type_node)
}

fn exact_constructed_type_target(
    type_node: Node<'_>,
    token: QueryToken<'_>,
    target: CodeUnit,
    name: &str,
    ctx: &ScalaScan<'_, '_>,
) -> Option<CodeUnit> {
    let resolved = ctx
        .types
        .resolve_type_application(
            ctx.scala,
            token,
            &ctx.resolver,
            Some(&target.fq_name()),
            None,
            name,
            call_site_shape_for_reference(type_node).as_ref(),
            TypeApplicationRole::ExplicitConstructor,
            Some(ctx.source_file),
        )
        .type_target?;
    (resolved == target).then_some(target)
}

fn unwrap_single_scala_expression(mut node: Node<'_>) -> Node<'_> {
    while matches!(node.kind(), "block" | "block_expression" | "indented_block")
        && node.named_child_count() == 1
    {
        node = node
            .named_child(0)
            .expect("a block with one named child has that child");
    }
    node
}

/// The anonymous template a `new T { .. }` initializer constructs.
///
/// `constructed_type_declaration` answers with the named base `T`, which is the
/// whole answer for `new T()` but loses every member the braces declare.
/// Extraction mints the template its own `CodeUnit` over exactly the
/// `instance_expression` span and records `T` among its supertypes, so an
/// initializer with a body is more precisely typed by the template than by the
/// base: the template's own members become reachable through the binding, and
/// members only `T` declares still resolve across the supertype edge. An
/// `instance_expression` with no body mints no unit, so this answers `None` and
/// the named base stays the receiver.
fn anonymous_template_declaration(node: Node<'_>, ctx: &ScalaScan<'_, '_>) -> Option<CodeUnit> {
    if node.kind() != "instance_expression" {
        return None;
    }
    ctx.class_ranges
        .unit_for_exact_span(node.start_byte(), node.end_byte())
        .cloned()
}

fn constructed_or_applied_type(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
) -> Option<ScalaValueOwner> {
    let node = unwrap_single_scala_expression(node);
    if let Some(template) = anonymous_template_declaration(node, ctx) {
        return Some(ScalaValueOwner::Exact(template));
    }
    constructed_type(node, token, ctx)
        .map(ScalaValueOwner::Logical)
        .or_else(|| {
            // `new Foreign()` with no Scala declaration: bind the value to the
            // constructed type when the realm proves it (#1859).
            let type_node = constructed_type_node(node)?;
            let path = scala_type_lookup_segments(type_node, ctx.source);
            if path.is_empty() {
                return None;
            }
            ctx.realm_foreign_type_fqn(&path, type_node.start_byte())
                .map(ScalaValueOwner::Logical)
        })
        .or_else(|| {
            if node.kind() != "call_expression" {
                return None;
            }
            let mut function = node.child_by_field_name("function")?;
            while function.kind() == "call_expression" {
                function = function.child_by_field_name("function")?;
            }
            function = invocation_function_reference(function);
            if !matches!(function.kind(), "identifier" | "type_identifier") {
                return None;
            }
            let name = node_text(function, ctx.source).trim();
            if name.is_empty() {
                return None;
            }
            let class_fqn = ctx.visible_type(token, function, name);
            let object_fqn = ctx
                .lexically_visible_object(function.start_byte(), name)
                .or_else(|| ctx.resolver.resolve_object(name));
            ctx.types
                .resolve_type_application(
                    ctx.scala,
                    token,
                    &ctx.resolver,
                    class_fqn.as_deref(),
                    object_fqn.as_deref(),
                    name,
                    call_site_shape_for_reference(function).as_ref(),
                    TypeApplicationRole::BareApplication,
                    Some(ctx.source_file),
                )
                .value_result
        })
}

fn call_result_type(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> Option<String> {
    let node = unwrap_single_scala_expression(node);
    if node.kind() != "call_expression" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    match function.kind() {
        "field_expression" => {
            let receiver = function.child_by_field_name("value")?;
            let field = function.child_by_field_name("field")?;
            let owner = receiver_value_owner(receiver, token, ctx, bindings)?;
            let method = node_text(field, ctx.source);
            if method == "copy" {
                match &owner {
                    ScalaValueOwner::Exact(owner) if ctx.types.is_case_class(ctx.scala, owner) => {
                        return Some(owner.fq_name());
                    }
                    ScalaValueOwner::Logical(owner) => {
                        let declarations = ctx.types.index.by_fqn(owner);
                        let mut candidates = declarations.iter().filter(|candidate| {
                            candidate.is_class() && ctx.types.is_case_class(ctx.scala, candidate)
                        });
                        let candidate = candidates.next()?.clone();
                        if candidates.next().is_none() {
                            return Some(candidate.fq_name());
                        }
                    }
                    ScalaValueOwner::Exact(_) => {}
                }
            }
            let call_arities = call_arities_for_reference(field);
            match &owner {
                ScalaValueOwner::Exact(owner) => ctx.types.member_return_type_for_members(
                    ctx.scala,
                    token,
                    &ctx.resolver,
                    &ctx.types
                        .members_for_exact_owner_unit(ctx.scala, owner, method),
                    call_arities.as_deref(),
                ),
                ScalaValueOwner::Logical(owner) => ctx.types.member_return_type_for_owner_member(
                    ctx.scala,
                    token,
                    &ctx.resolver,
                    owner,
                    method,
                    call_arities.as_deref(),
                ),
            }
        }
        "identifier" => {
            let method = node_text(function, ctx.source);
            if bindings.is_shadowed(method) {
                return recursive_enclosing_function_return_type(function, token, method, ctx);
            }
            if !bindings.resolve_symbol(method).is_unknown() {
                return None;
            }
            let call_arities = call_arities_for_reference(function);
            match lexically_visible_unqualified_member_return_type(
                function,
                token,
                method,
                call_arities.as_deref(),
                ctx,
            ) {
                MemberReturnResolution::Resolved(return_type) => Some(return_type),
                MemberReturnResolution::NoMatch => {
                    ctx.resolver.resolve_member(method).and_then(|member| {
                        ctx.types.member_return_type_for_fqn_call(
                            ctx.scala,
                            token,
                            &ctx.resolver,
                            &member,
                            call_arities.as_deref(),
                        )
                    })
                }
                MemberReturnResolution::Unresolved => None,
            }
        }
        _ => None,
    }
}

fn recursive_enclosing_function_return_type(
    node: Node<'_>,
    token: QueryToken<'_>,
    method: &str,
    ctx: &ScalaScan<'_, '_>,
) -> Option<String> {
    let mut current = Some(node);
    while let Some(candidate) = current {
        let function = candidate.parent()?;
        if function.kind() == "function_definition"
            && function.child_by_field_name("body") == Some(candidate)
        {
            let name = function.child_by_field_name("name")?;
            if node_text(name, ctx.source).trim() != method {
                return None;
            }
            return function
                .child_by_field_name("return_type")
                .and_then(|type_node| resolve_receiver_type_node(type_node, token, ctx));
        }
        current = Some(function);
    }
    None
}

fn lexically_visible_unqualified_member_return_type(
    node: Node<'_>,
    token: QueryToken<'_>,
    member: &str,
    call_arities: Option<&[usize]>,
    ctx: &ScalaScan<'_, '_>,
) -> MemberReturnResolution {
    for declaration in enclosing_template_declarations(node) {
        let resolution = if let Some(owner) = ctx
            .class_ranges
            .unit_for_exact_span(declaration.start_byte(), declaration.end_byte())
        {
            ctx.types.unqualified_member_return_type(
                ctx.scala,
                token,
                &ctx.resolver,
                owner,
                member,
                call_arities,
            )
        } else if template_direct_term_member_named(declaration, member, ctx.source) {
            MemberReturnResolution::Unresolved
        } else {
            let Some(owners) = template_supertype_owners(declaration, token, ctx) else {
                return MemberReturnResolution::Unresolved;
            };
            ctx.types.unqualified_member_return_type_for_owners(
                ctx.scala,
                token,
                &ctx.resolver,
                &owners,
                member,
                call_arities,
            )
        };
        match resolution {
            MemberReturnResolution::NoMatch => {}
            resolution => return resolution,
        }
        for self_type in template_self_types(declaration) {
            let Some(self_owner) = resolve_receiver_type_node(self_type, token, ctx) else {
                continue;
            };
            let mut declarations = ctx
                .types
                .definitions(&self_owner)
                .into_iter()
                .filter(CodeUnit::is_class);
            let Some(declaration) = declarations.next() else {
                continue;
            };
            if declarations.next().is_some() {
                return MemberReturnResolution::Unresolved;
            }
            match ctx.types.unqualified_member_return_type(
                ctx.scala,
                token,
                &ctx.resolver,
                &declaration,
                member,
                call_arities,
            ) {
                MemberReturnResolution::NoMatch => {}
                resolution => return resolution,
            }
        }
    }
    MemberReturnResolution::NoMatch
}

fn seed_binding(
    name: &str,
    receiver_type: Option<String>,
    declaration_owner: Option<CodeUnit>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    seed_scala_binding(name, receiver_type, declaration_owner, bindings);
}

fn seed_value_owner(
    name: &str,
    receiver: Option<ScalaValueOwner>,
    declaration_owner: Option<CodeUnit>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    match receiver {
        Some(ScalaValueOwner::Exact(receiver)) => seed_scala_binding_with_receiver_declaration(
            name,
            receiver,
            declaration_owner,
            bindings,
        ),
        Some(ScalaValueOwner::Logical(receiver)) => {
            seed_binding(name, Some(receiver), declaration_owner, bindings)
        }
        None => seed_binding(name, None, declaration_owner, bindings),
    }
}

fn exactify_value_owner(
    owner: ScalaValueOwner,
    reference_start_byte: usize,
    ctx: &ScalaScan<'_, '_>,
) -> Option<ScalaValueOwner> {
    match owner {
        ScalaValueOwner::Exact(owner) => Some(ScalaValueOwner::Exact(owner)),
        ScalaValueOwner::Logical(receiver_type) => {
            let Some(owner_context) = ctx.enclosing_class_unit(reference_start_byte) else {
                return Some(ScalaValueOwner::Logical(receiver_type));
            };
            exact_receiver_type_declaration(&receiver_type, owner_context, ctx)
                .map(ScalaValueOwner::Exact)
                .or(Some(ScalaValueOwner::Logical(receiver_type)))
        }
    }
}

fn exact_owner_field_binding(
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
    name: &str,
) -> Option<CodeUnit> {
    precise_scala_binding(bindings, name).and_then(|binding| binding.declaration_owner)
}

/// The foreign (non-Scala) type a written type node names, when the realm
/// proves exactly one expansion of its path exists (#1859). Runs only after
/// the physical Scala tiers have missed: a name the Scala index resolves never
/// reaches here, so this cannot rebind a Scala type to a foreign one.
fn resolve_foreign_receiver_type_node(
    type_node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
) -> Option<String> {
    let type_node = scala_capture_underlying_type(type_node, ctx.source);
    let path = scala_type_lookup_segments(type_node, ctx.source);
    if path.is_empty() {
        return None;
    }
    ctx.realm_foreign_type_fqn(&path, type_node.start_byte())
}

/// The dotted path a receiver *expression* spells when it is a plain qualified
/// name — `Config`, `msg.Entry`, `com.example.JarManifest` — or `None` when
/// any part of it is a value computation (a call, an application, `this`)
/// rather than a name. Iterative: the chain is a linked list of
/// `field_expression` nodes.
fn receiver_static_path_segments(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut segments = Vec::new();
    let mut current = node;
    loop {
        match current.kind() {
            "identifier" | "type_identifier" => {
                let name = node_text(current, source).trim().trim_end_matches('$');
                if name.is_empty() {
                    return None;
                }
                segments.push(name.to_string());
                break;
            }
            "field_expression" => {
                let field = current.child_by_field_name("field")?;
                let member = node_text(field, source).trim().trim_end_matches('$');
                if member.is_empty() {
                    return None;
                }
                segments.push(member.to_string());
                current = current.child_by_field_name("value")?;
            }
            _ => return None,
        }
    }
    segments.reverse();
    Some(segments)
}

/// The receiver expression as a foreign type written in receiver position —
/// `Config.of(..)`, `msg.Entry.parse(..)` — proven against the realm (#1859).
/// A name the local value bindings know (or shadow) is a value, not a type
/// path, and is left to the unproven channel.
fn realm_static_owner_fqn(
    receiver: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> Option<String> {
    let segments = receiver_static_path_segments(receiver, ctx.source)?;
    let head = segments.first()?;
    if !bindings.resolve_symbol(head).is_unknown() || bindings.is_shadowed(head) {
        return None;
    }
    ctx.realm_foreign_type_fqn(&segments, receiver.start_byte())
}

fn resolve_receiver_type_node(
    type_node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
) -> Option<String> {
    let type_node = scala_capture_underlying_type(type_node, ctx.source);
    let path = scala_type_lookup_segments(type_node, ctx.source);
    if path.is_empty() {
        return None;
    }
    let resolved = if path.len() > 1
        && let Some(root) = path
            .first()
            .and_then(|root| ctx.lexically_visible_object_unit(type_node.start_byte(), root))
        && let Some(declaration) = ctx.types.resolve_qualified_stable_type_unit_at(
            ctx.scala,
            &ctx.resolver,
            &path,
            false,
            Some(root),
        ) {
        Some(declaration.fq_name())
    } else {
        match ctx.exact_lexically_visible_type(token, type_node) {
            ScalaTypeNamespaceResolution::Resolved(declaration) => Some(declaration.fq_name()),
            ScalaTypeNamespaceResolution::AuthoritativeMiss
            | ScalaTypeNamespaceResolution::Ambiguous(_) => return None,
            ScalaTypeNamespaceResolution::NoMatch => ctx
                .types
                .resolve_type_in_declaration_context(ctx.scala, &ctx.resolver, &path)
                .or_else(|| {
                    (path.len() == 1)
                        .then(|| scala_builtin_type_name(&path[0]).map(str::to_string))
                        .flatten()
                }),
        }
    }?;
    ctx.types
        .canonical_receiver_type(ctx.scala, token, &resolved)
}

fn resolve_receiver_type_declaration_node(
    type_node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScalaScan<'_, '_>,
) -> Option<CodeUnit> {
    let type_node = scala_capture_underlying_type(type_node, ctx.source);
    let path = scala_type_lookup_segments(type_node, ctx.source);
    let declaration = if path.len() > 1
        && let Some(root) = path
            .first()
            .and_then(|root| ctx.lexically_visible_object_unit(type_node.start_byte(), root))
        && let Some(declaration) = ctx.types.resolve_qualified_stable_type_unit_at(
            ctx.scala,
            &ctx.resolver,
            &path,
            false,
            Some(root),
        ) {
        declaration
    } else {
        match ctx.exact_lexically_visible_type(token, type_node) {
            ScalaTypeNamespaceResolution::Resolved(declaration) => declaration,
            ScalaTypeNamespaceResolution::AuthoritativeMiss
            | ScalaTypeNamespaceResolution::Ambiguous(_) => return None,
            // Single-unit by contract: this answers "which declaration node is
            // this receiver's type", which is a one-declaration question. The
            // plural replica resolver (#2021) has nothing to say here, because
            // a caller that needs several answers would need a different
            // return type, not a different lookup.
            ScalaTypeNamespaceResolution::NoMatch if path.len() == 1 => {
                ctx.resolver.resolve_unit(&path[0])?
            }
            ScalaTypeNamespaceResolution::NoMatch => return None,
        }
    };
    if !ctx.types.is_type_alias(ctx.scala, &declaration) {
        return Some(declaration);
    }
    let receiver_type =
        ctx.types
            .canonical_receiver_type(ctx.scala, token, &declaration.fq_name())?;
    let owner_context = ctx
        .types
        .exact_structural_parent(ctx.scala, &declaration)
        .unwrap_or_else(|| declaration.clone());
    match ctx
        .types
        .exact_type_declaration_for_owner_context(&receiver_type, &owner_context)
    {
        ScalaTypeNamespaceResolution::Resolved(declaration) => Some(declaration),
        ScalaTypeNamespaceResolution::AuthoritativeMiss
        | ScalaTypeNamespaceResolution::Ambiguous(_)
        | ScalaTypeNamespaceResolution::NoMatch => None,
    }
}

/// Tree-sitter represents Scala 3's postfix capture marker (`T^`) as an
/// `infix_type` whose right operand is the zero-width missing node. Preserve
/// the parser's structure while resolving the actual receiver type on the
/// left; ordinary infix/intersection types remain untouched.
fn scala_capture_underlying_type<'tree>(type_node: Node<'tree>, source: &str) -> Node<'tree> {
    if type_node.kind() == "infix_type"
        && type_node
            .child_by_field_name("operator")
            .is_some_and(|operator| node_text(operator, source).trim() == "^")
        && type_node
            .child_by_field_name("right")
            .is_some_and(|right| right.start_byte() == right.end_byte())
        && let Some(left) = type_node.child_by_field_name("left")
    {
        return left;
    }
    type_node
}

fn visible_extensions(
    ctx: &ScalaScan<'_, '_>,
    token: QueryToken<'_>,
    member: &str,
    receiver_owner: Option<&str>,
    call_arities: Option<&[usize]>,
) -> Vec<ExtensionMethod> {
    let mut visible = ctx
        .resolver
        .visible_extension_methods(ctx.scala, token, ctx.types, member);
    visible.sort_by(|left, right| left.declaration.cmp(&right.declaration));
    visible.dedup_by(|left, right| left.declaration == right.declaration);
    let receiver_matches = |method: &ExtensionMethod| {
        method.alternatives.iter().any(|alternative| {
            alternative.role == ScalaCallableRole::Ordinary
                && extension_alternative_receiver_matches(
                    &ctx.resolver,
                    alternative,
                    receiver_owner,
                )
        })
    };
    // "Unique callable" leniency spans the whole overload family of every
    // receiver-matching method, receiver-incompatible siblings included:
    // before #1327 the family was one merged unit whose alternative list
    // carried them all, and an unapplied method value over an overloaded
    // extension must stay ambiguous.
    let callable_count = visible
        .iter()
        .filter(|method| {
            visible.iter().any(|candidate| {
                receiver_matches(candidate)
                    && same_overload_family(&candidate.declaration, &method.declaration)
            })
        })
        .flat_map(|method| method.alternatives.iter())
        .filter(|alternative| alternative.role == ScalaCallableRole::Ordinary)
        .count();
    let unique_callable = callable_count == 1;
    let mut matches = visible;
    matches.retain(|method| {
        method.alternatives.iter().any(|alternative| {
            alternative.role == ScalaCallableRole::Ordinary
                && extension_alternative_receiver_matches(
                    &ctx.resolver,
                    alternative,
                    receiver_owner,
                )
                && ordinary_callable_shape_matches(alternative, call_arities, unique_callable)
        })
    });
    matches
}

fn extension_alternative_receiver_matches(
    resolver: &NameResolver,
    alternative: &CallableAlternative,
    receiver_owner: Option<&str>,
) -> bool {
    scala_extension_receiver_matches_resolved(
        alternative.extension_receiver_type.as_deref(),
        receiver_owner,
        |type_text| {
            resolver
                .resolve(type_text)
                .or_else(|| scala_builtin_type_name(type_text).map(str::to_string))
        },
    )
}

fn has_ancestor_kind(node: Node<'_>, kind: &str) -> bool {
    let mut parent = node.parent();
    while let Some(current) = parent {
        if current.kind() == kind {
            return true;
        }
        parent = current.parent();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::model::CodeUnitType;

    /// The cross-built shape of #2021: one logical `com.example.Probe`
    /// declared by a `scala-2` file and a `scala-3` file.
    fn scala2_file() -> ProjectFile {
        ProjectFile::new(
            std::env::temp_dir(),
            "src/main/scala-2/com/example/Probe.scala",
        )
    }

    fn scala3_file() -> ProjectFile {
        ProjectFile::new(
            std::env::temp_dir(),
            "src/main/scala-3/com/example/Probe.scala",
        )
    }

    fn unit(
        source: ProjectFile,
        kind: CodeUnitType,
        package_name: &str,
        short_name: &str,
        signature: Option<&str>,
        synthetic: bool,
    ) -> CodeUnit {
        CodeUnit::with_signature(
            source,
            kind,
            package_name,
            short_name,
            signature.map(str::to_string),
            synthetic,
        )
    }

    fn probe(source: ProjectFile) -> CodeUnit {
        unit(
            source,
            CodeUnitType::Class,
            "com.example",
            "Probe",
            None,
            false,
        )
    }

    /// The central case: two declarations that differ only in which file
    /// declares them are one replica family, and are NOT one overload family.
    #[test]
    fn a_source_only_difference_is_a_replica_family_but_not_an_overload_family() {
        let left = probe(scala2_file());
        let right = probe(scala3_file());
        assert!(same_replica_family(&left, &right));
        assert!(!same_overload_family(&left, &right));
        assert!(single_replica_family([&left, &right].into_iter()));
        assert!(!single_overload_family([&left, &right].into_iter()));
    }

    /// Signature is excluded from replica identity exactly as it is excluded
    /// from overload identity, so cross-built overloads still group.
    #[test]
    fn a_source_and_signature_difference_is_still_a_replica_family() {
        let left = unit(
            scala2_file(),
            CodeUnitType::Function,
            "com.example",
            "Probe.read",
            Some("()"),
            false,
        );
        let right = unit(
            scala3_file(),
            CodeUnitType::Function,
            "com.example",
            "Probe.read",
            Some("(String)"),
            false,
        );
        assert!(same_replica_family(&left, &right));
    }

    /// A class and a function of the same name are different declarations.
    #[test]
    fn a_kind_mismatch_is_not_a_replica_family() {
        let left = probe(scala2_file());
        let right = unit(
            scala3_file(),
            CodeUnitType::Function,
            "com.example",
            "Probe",
            None,
            false,
        );
        assert!(!same_replica_family(&left, &right));
    }

    /// Two packages are two symbols however alike their tails read.
    #[test]
    fn a_package_mismatch_is_not_a_replica_family() {
        let left = probe(scala2_file());
        let right = unit(
            scala3_file(),
            CodeUnitType::Class,
            "com.other",
            "Probe",
            None,
            false,
        );
        assert!(!same_replica_family(&left, &right));
    }

    /// `class Probe` and `object Probe` normalize to the same fully qualified
    /// name, so this pins that the predicate reads the short name it is given
    /// rather than a normalized rendering of it.
    #[test]
    fn a_class_and_its_object_singleton_are_not_a_replica_family() {
        let left = probe(scala2_file());
        let right = unit(
            scala3_file(),
            CodeUnitType::Class,
            "com.example",
            "Probe$",
            None,
            false,
        );
        assert!(!same_replica_family(&left, &right));
    }

    /// A compiler-implied declaration is not a replica of a written one.
    #[test]
    fn a_synthetic_flag_mismatch_is_not_a_replica_family() {
        let left = probe(scala2_file());
        let right = unit(
            scala3_file(),
            CodeUnitType::Class,
            "com.example",
            "Probe",
            None,
            true,
        );
        assert!(!same_replica_family(&left, &right));
    }

    /// Empty sets are vacuously a single family, matching
    /// [`single_overload_family`]; gates check emptiness themselves.
    #[test]
    fn an_empty_set_is_vacuously_a_single_replica_family() {
        assert!(single_replica_family(std::iter::empty()));
        assert!(single_overload_family(std::iter::empty()));
    }

    /// `same_overload_family` is `same_replica_family` plus source equality,
    /// so every set the overload gate admits the replica gate admits too. This
    /// pins the implication in code so a later edit cannot break it silently.
    #[test]
    fn a_same_file_overload_family_is_also_a_single_replica_family() {
        let file = scala2_file();
        let first = unit(
            file.clone(),
            CodeUnitType::Function,
            "com.example",
            "Probe.read",
            Some("()"),
            false,
        );
        let second = unit(
            file,
            CodeUnitType::Function,
            "com.example",
            "Probe.read",
            Some("(String)"),
            false,
        );
        assert!(single_overload_family([&first, &second].into_iter()));
        assert!(single_replica_family([&first, &second].into_iter()));
    }

    /// One disagreeing member spoils the whole set; incoherent sets fail closed.
    #[test]
    fn one_incoherent_member_breaks_a_three_element_replica_family() {
        let first = probe(scala2_file());
        let second = probe(scala3_file());
        let third = unit(
            ProjectFile::new(
                std::env::temp_dir(),
                "src/main/scala/com/example/Probe.scala",
            ),
            CodeUnitType::Class,
            "com.example",
            "Probe$",
            None,
            false,
        );
        assert!(single_replica_family([&first, &second].into_iter()));
        assert!(!single_replica_family(
            [&first, &second, &third].into_iter()
        ));
    }
}
