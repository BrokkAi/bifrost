//! The targeted find-references scan: which declarations a query is really
//! asking about, and what a matched reference means for them.
//!
//! The strategy shell around this stays in `brokk-bifrost-analysis` --
//! `UsageQueryResolver`, `UsageScanScope` and `GraphUsageOutcome` are
//! analysis-owned traits, and so is the cross-language Kotlin file sweep a
//! Scala type query fans out to. What is here is the resolution: the per-query
//! catalog that projects each target onto the reference roles, owners,
//! companions and import spellings that can name it, and the sink that decides
//! which of the scanner's events belong to which target.

use crate::java::graph::resolver::{self as java_resolver, java_callable_arity};
use crate::java::graph_support::JavaSource;
use crate::scala::graph::inverted::{
    ScalaLogicalOwnerMember, ScalaLogicalReceiver, ScalaReferenceRole, ScalaReferenceSink,
    ScalaResolvedReference, callable_alternative_contradicts_literal_arguments,
    callable_alternative_is_candidate, callable_alternative_matches, single_replica_family,
};
use crate::scala::graph::resolver::{
    TargetKind, TargetSpec, import_candidate_fq_names, member_matches_target_kind,
    scala_normalized_fq_name,
};
use crate::scala::graph::syntax::{ScalaCallSiteShape, ScalaCallableSiteRole};
use crate::scala::graph_support::{ScalaSource, ScalaWorkspaceSource};
use crate::scala::wildcard_imports::scala_import_path;
use crate::scala::{scala_nested_type_candidates, scala_short_name_terminal_segment};
use brokk_bifrost_core::analyzer::model::{CallableArity, ImportInfo};
use brokk_bifrost_core::analyzer::usages::common::{
    SNIPPET_CONTEXT_LINES, external_usage_hit_count, usage_hit,
};
use brokk_bifrost_core::analyzer::usages::inverted_edges::{ClassRangeIndex, UsageReferenceKind};
use brokk_bifrost_core::analyzer::usages::model::{UsageHit, UsageHitKind};
use brokk_bifrost_core::analyzer::{CodeUnit, Language, ProjectFile, Range};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_core::text_utils::{find_line_index_for_offset, snippet_around_line};
use std::collections::BTreeSet;

pub struct ScalaQueryTargetCatalog {
    targets: Vec<CodeUnit>,
    specs: Vec<TargetSpec>,
    exact: HashMap<(CodeUnit, ScalaReferenceRole), Vec<usize>>,
    exact_owner_members: HashMap<(CodeUnit, String, ScalaReferenceRole), Vec<usize>>,
    logical: HashMap<(String, ScalaReferenceRole), Vec<usize>>,
    explicit_imports: HashMap<String, Vec<usize>>,
    owner_imports: HashMap<String, Vec<usize>>,
    /// Member targets whose declarations no Scala index can hold (#1859):
    /// keyed by (normalized owner fqn, member name). Never mixed with the
    /// Scala-keyed maps above -- a catalog serves either Scala targets or one
    /// foreign JVM target family, and the `CodeUnit`-keyed buckets stay empty
    /// for the latter so identity never depends on `CodeUnit` equality across
    /// the language seam (#1239).
    foreign_members: HashMap<(String, String), Vec<usize>>,
    /// Foreign *type* targets, keyed by normalized fqn: the type itself for
    /// `Type` targets, the owner for `Constructor` targets (`new Owner(..)` is
    /// a type reference whose arity the sink checks separately).
    foreign_types: HashMap<String, Vec<usize>>,
    foreign_specs: Vec<ForeignJvmMemberSpec>,
}

/// The Java/Kotlin member shape of a foreign catalog target. Arity families
/// are split by staticness because a Java overload family may mix both
/// (`static read(String)` beside `read(int)`), and only the style matching the
/// written receiver may hit.
pub struct ForeignJvmMemberSpec {
    pub kind: java_resolver::TargetKind,
    pub member_name: String,
    pub static_callable_arities: HashSet<CallableArity>,
    pub instance_callable_arities: HashSet<CallableArity>,
    pub has_static_field: bool,
    pub has_instance_field: bool,
}

impl ForeignJvmMemberSpec {
    /// Whether a member event written through this receiver style can name the
    /// target family. `call_shape` is present for call sites and absent for
    /// bare selections; a bare selection names the whole family, matching the
    /// retired duplicate scanner's paren-less rule (#1859).
    fn accepts(
        &self,
        receiver: ScalaLogicalReceiver,
        role: ScalaReferenceRole,
        call_shape: Option<&ScalaCallSiteShape>,
    ) -> bool {
        let is_static = receiver == ScalaLogicalReceiver::StaticOwner;
        match self.kind {
            java_resolver::TargetKind::Type | java_resolver::TargetKind::Constructor => false,
            java_resolver::TargetKind::Field => {
                role == ScalaReferenceRole::Field
                    && if is_static {
                        self.has_static_field
                    } else {
                        self.has_instance_field
                    }
            }
            java_resolver::TargetKind::Method => {
                let arities = if is_static {
                    &self.static_callable_arities
                } else {
                    &self.instance_callable_arities
                };
                if arities.is_empty() {
                    return false;
                }
                let Some(shape) = call_shape.filter(|_| role == ScalaReferenceRole::Callable)
                else {
                    // A paren-less selection or method value names the family.
                    return true;
                };
                // Java callables take exactly one argument list; a curried or
                // type-only application can only be a Scala construct.
                if shape.type_arguments_only || shape.lists.len() != 1 {
                    return false;
                }
                let actual = shape.lists[0].arity;
                arities.iter().any(|expected| expected.accepts(actual))
            }
        }
    }
}

pub enum ScalaCatalogBuildError {
    Cancelled,
    UnsupportedTarget(CodeUnit),
}

fn ensure_catalog_active(
    cancellation: Option<&CancellationToken>,
) -> Result<(), ScalaCatalogBuildError> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        Err(ScalaCatalogBuildError::Cancelled)
    } else {
        Ok(())
    }
}

impl ScalaQueryTargetCatalog {
    pub fn build(
        scala: &dyn ScalaSource,
        targets: &[CodeUnit],
        cancellation: Option<&CancellationToken>,
    ) -> Result<Self, ScalaCatalogBuildError> {
        ensure_catalog_active(cancellation)?;
        let mut exact: HashMap<(CodeUnit, ScalaReferenceRole), Vec<usize>> = HashMap::default();
        let mut exact_owner_members: HashMap<(CodeUnit, String, ScalaReferenceRole), Vec<usize>> =
            HashMap::default();
        let mut explicit_imports: HashMap<String, Vec<usize>> = HashMap::default();
        let mut owner_imports: HashMap<String, Vec<usize>> = HashMap::default();
        let mut direct_descendants: HashMap<CodeUnit, Vec<CodeUnit>> = HashMap::default();
        if let Some(ancestors_by_unit) = scala.project_types().exact_direct_ancestors_snapshot() {
            for (unit, ancestors) in ancestors_by_unit {
                ensure_catalog_active(cancellation)?;
                for ancestor in ancestors {
                    ensure_catalog_active(cancellation)?;
                    direct_descendants
                        .entry(ancestor.clone())
                        .or_default()
                        .push(unit.clone());
                }
            }
        }
        let mut specs = Vec::with_capacity(targets.len());
        for (target_id, target) in targets.iter().enumerate() {
            ensure_catalog_active(cancellation)?;
            let spec = TargetSpec::from_target(scala, target)
                .ok_or_else(|| ScalaCatalogBuildError::UnsupportedTarget(target.clone()))?;
            if matches!(spec.kind, TargetKind::Method | TargetKind::Field) {
                let role = if spec.kind == TargetKind::Field {
                    ScalaReferenceRole::Field
                } else {
                    ScalaReferenceRole::Callable
                };
                for owner in &spec.receiver_owners {
                    ensure_catalog_active(cancellation)?;
                    exact_owner_members
                        .entry((owner.clone(), spec.member_name.clone(), role))
                        .or_default()
                        .push(target_id);
                }
            }
            let direct_roles: &[ScalaReferenceRole] = match spec.kind {
                TargetKind::Type if spec.is_object_type => {
                    &[ScalaReferenceRole::Type, ScalaReferenceRole::StableObject]
                }
                TargetKind::Type => &[ScalaReferenceRole::Type],
                TargetKind::Constructor => &[
                    ScalaReferenceRole::Callable,
                    ScalaReferenceRole::CompanionApplication,
                    ScalaReferenceRole::CompanionExtractor,
                ],
                TargetKind::Method => &[ScalaReferenceRole::Callable, ScalaReferenceRole::Override],
                TargetKind::Field => &[ScalaReferenceRole::Field],
            };
            for role in direct_roles.iter().copied() {
                ensure_catalog_active(cancellation)?;
                exact
                    .entry((target.clone(), role))
                    .or_default()
                    .push(target_id);
            }
            if spec.accepts_term_field_role {
                exact
                    .entry((target.clone(), ScalaReferenceRole::Field))
                    .or_default()
                    .push(target_id);
            }
            if spec.kind == TargetKind::Type && spec.accepts_apply_role {
                exact
                    .entry((target.clone(), ScalaReferenceRole::CompanionValue))
                    .or_default()
                    .push(target_id);
                for constructor in scala.project_types().exact_member_declarations(
                    scala,
                    target,
                    target.identifier(),
                ) {
                    ensure_catalog_active(cancellation)?;
                    if constructor.is_function() {
                        for role in [
                            ScalaReferenceRole::CompanionApplication,
                            ScalaReferenceRole::CompanionValue,
                        ] {
                            exact
                                .entry((constructor.clone(), role))
                                .or_default()
                                .push(target_id);
                        }
                    }
                }
                let normalized_target = scala_normalized_fq_name(&target.fq_name());
                for companion in scala.project_types().exact_companion_objects(scala, target) {
                    ensure_catalog_active(cancellation)?;
                    for apply in scala
                        .project_types()
                        .exact_member_declarations(scala, &companion, "apply")
                    {
                        ensure_catalog_active(cancellation)?;
                        if !apply.is_function()
                            || !scala
                                .project_types()
                                .callable_alternatives_for(scala, &apply)
                                .iter()
                                .any(|alternative| {
                                    alternative
                                        .return_type
                                        .as_deref()
                                        .is_some_and(|return_type| {
                                            scala_normalized_fq_name(return_type)
                                                == normalized_target
                                        })
                                })
                        {
                            continue;
                        }
                        for role in [
                            ScalaReferenceRole::CompanionApplication,
                            ScalaReferenceRole::CompanionValue,
                        ] {
                            exact
                                .entry((apply.clone(), role))
                                .or_default()
                                .push(target_id);
                        }
                    }
                }
            }
            if spec.kind == TargetKind::Type && spec.is_object_type {
                for class in scala.project_types().exact_companion_classes(scala, target) {
                    ensure_catalog_active(cancellation)?;
                    if !scala.project_types().is_case_class(scala, &class) {
                        continue;
                    }
                    for constructor in scala.project_types().exact_member_declarations(
                        scala,
                        &class,
                        class.identifier(),
                    ) {
                        ensure_catalog_active(cancellation)?;
                        if constructor.is_function() && constructor.is_synthetic() {
                            for role in [
                                ScalaReferenceRole::CompanionApplication,
                                ScalaReferenceRole::CompanionExtractor,
                            ] {
                                exact
                                    .entry((constructor.clone(), role))
                                    .or_default()
                                    .push(target_id);
                            }
                        }
                    }
                }
                for member_name in ["apply", "unapply", "unapplySeq"] {
                    ensure_catalog_active(cancellation)?;
                    for member in
                        scala
                            .project_types()
                            .exact_member_declarations(scala, target, member_name)
                    {
                        ensure_catalog_active(cancellation)?;
                        if member.is_function() {
                            exact
                                .entry((
                                    member.clone(),
                                    if member_name == "apply" {
                                        ScalaReferenceRole::CompanionApplication
                                    } else {
                                        ScalaReferenceRole::CompanionExtractor
                                    },
                                ))
                                .or_default()
                                .push(target_id);
                            if member_name == "apply" {
                                exact
                                    .entry((member, ScalaReferenceRole::CompanionValue))
                                    .or_default()
                                    .push(target_id);
                            }
                        }
                    }
                }
            }
            if spec.kind == TargetKind::Type && scala.project_types().is_enum(scala, target) {
                for candidate in scala.get_declarations(target.source()) {
                    ensure_catalog_active(cancellation)?;
                    if candidate.is_field()
                        && scala.structural_parent_of(&candidate).as_ref() == Some(target)
                    {
                        for role in [
                            ScalaReferenceRole::Field,
                            ScalaReferenceRole::StableObject,
                            ScalaReferenceRole::Type,
                        ] {
                            exact
                                .entry((candidate.clone(), role))
                                .or_default()
                                .push(target_id);
                        }
                    }
                }
            }
            match spec.kind {
                TargetKind::Type => {}
                TargetKind::Method | TargetKind::Field => {
                    for owner in &spec.family_owners {
                        ensure_catalog_active(cancellation)?;
                        for candidate in
                            scala.definitions(&format!("{}.{}", owner.fq_name(), spec.member_name))
                        {
                            ensure_catalog_active(cancellation)?;
                            if scala.structural_parent_of(&candidate).as_ref() != Some(owner) {
                                continue;
                            }
                            let compatible = member_matches_target_kind(
                                scala, &candidate, spec.kind, spec.arity,
                            );
                            if compatible {
                                let roles: &[ScalaReferenceRole] = match spec.kind {
                                    TargetKind::Method => &[
                                        ScalaReferenceRole::Callable,
                                        ScalaReferenceRole::Override,
                                    ],
                                    TargetKind::Field => &[ScalaReferenceRole::Field],
                                    TargetKind::Type | TargetKind::Constructor => unreachable!(),
                                };
                                for role in roles.iter().copied() {
                                    exact
                                        .entry((candidate.clone(), role))
                                        .or_default()
                                        .push(target_id);
                                }
                            }
                        }
                    }
                    if spec.accepts_field_implementation
                        && let Some(contract_owner) = spec.owner.as_ref()
                    {
                        for descendant in self::exact_descendants_including_self(
                            &direct_descendants,
                            contract_owner,
                            cancellation,
                        )? {
                            ensure_catalog_active(cancellation)?;
                            let candidates = scala.project_types().exact_member_declarations(
                                scala,
                                &descendant,
                                &spec.member_name,
                            );
                            exact_owner_members
                                .entry((
                                    descendant.clone(),
                                    spec.member_name.clone(),
                                    ScalaReferenceRole::Field,
                                ))
                                .or_default()
                                .push(target_id);
                            for candidate in candidates {
                                ensure_catalog_active(cancellation)?;
                                if candidate.is_field() {
                                    for role in
                                        [ScalaReferenceRole::Field, ScalaReferenceRole::Callable]
                                    {
                                        exact
                                            .entry((candidate.clone(), role))
                                            .or_default()
                                            .push(target_id);
                                    }
                                }
                            }
                        }
                    }
                    if spec.kind == TargetKind::Method
                        && matches!(
                            spec.member_name.as_str(),
                            "apply" | "unapply" | "unapplySeq"
                        )
                    {
                        exact
                            .entry((
                                target.clone(),
                                if spec.member_name == "apply" {
                                    ScalaReferenceRole::CompanionApplication
                                } else {
                                    ScalaReferenceRole::CompanionExtractor
                                },
                            ))
                            .or_default()
                            .push(target_id);
                        if spec.member_name == "apply" {
                            exact
                                .entry((target.clone(), ScalaReferenceRole::CompanionValue))
                                .or_default()
                                .push(target_id);
                        }
                    }
                    if spec.kind == TargetKind::Method && spec.accepts_companion_apply_syntax {
                        // Only the target's own events: a case class's
                        // generated apply is a distinct overload whose call
                        // sites belong to the class/constructor targets, not
                        // to a specific explicit `apply` overload (#1327).
                        for role in [
                            ScalaReferenceRole::CompanionApplication,
                            ScalaReferenceRole::CompanionValue,
                        ] {
                            ensure_catalog_active(cancellation)?;
                            exact
                                .entry((target.clone(), role))
                                .or_default()
                                .push(target_id);
                        }
                    }
                }
                TargetKind::Constructor => {}
            }
            explicit_imports
                .entry(scala_normalized_fq_name(&spec.target_fq_name))
                .or_default()
                .push(target_id);
            if spec.kind == TargetKind::Type {
                owner_imports
                    .entry(scala_normalized_fq_name(&spec.target_fq_name))
                    .or_default()
                    .push(target_id);
            }
            specs.push(spec);
        }
        for target_ids in exact.values_mut() {
            ensure_catalog_active(cancellation)?;
            target_ids.sort_unstable();
            target_ids.dedup();
        }
        for target_ids in exact_owner_members.values_mut() {
            ensure_catalog_active(cancellation)?;
            target_ids.sort_unstable();
            target_ids.dedup();
        }
        for target_ids in explicit_imports
            .values_mut()
            .chain(owner_imports.values_mut())
        {
            ensure_catalog_active(cancellation)?;
            target_ids.sort_unstable();
            target_ids.dedup();
        }
        // The whole-graph scanner still has a few resolution paths whose
        // authoritative result is an FQN. They are safe for exact query
        // buckets only when the analyzer proves that FQN names one logical
        // declaration project-wide. Cross-built source sets declare one logical
        // symbol several times, so a coherent replica family counts as one
        // declaration and the bucket carries every member's target id (#2021);
        // a candidate set that disagrees on an identity field is a genuine
        // collision and keeps the reference ambiguous. Uniqueness among the
        // requested targets is still not enough on its own: the family is
        // derived from the workspace declarations, not from the request.
        //
        // This loop runs once per family member and every member writes the
        // same logical key, so the values accumulate rather than being
        // inserted. A plain insert would let one arbitrary member win, and
        // because HashMap iteration order is not deterministic, which one won
        // would vary between runs.
        let mut logical: HashMap<(String, ScalaReferenceRole), Vec<usize>> = HashMap::default();
        for ((unit, role), target_ids) in &exact {
            ensure_catalog_active(cancellation)?;
            let declarations = scala.definitions(&unit.fq_name()).collect::<Vec<_>>();
            if declarations.contains(unit) && single_replica_family(declarations.iter()) {
                logical
                    .entry((unit.fq_name(), *role))
                    .or_default()
                    .extend(target_ids.iter().copied());
            }
        }
        for target_ids in logical.values_mut() {
            ensure_catalog_active(cancellation)?;
            target_ids.sort_unstable();
            target_ids.dedup();
        }

        Ok(Self {
            targets: targets.to_vec(),
            specs,
            exact,
            exact_owner_members,
            logical,
            explicit_imports,
            owner_imports,
            foreign_members: HashMap::default(),
            foreign_types: HashMap::default(),
            foreign_specs: Vec::new(),
        })
    }

    /// Build the catalog for a foreign (Java/Kotlin) target family from the
    /// *Java-side* [`java_resolver::TargetSpec`] the call sites already hold,
    /// so overload and arity selection follow Java's own rules (#1859). No
    /// Scala `TargetSpec::from_target` runs: the target's source is not Scala
    /// and the Scala grammar has nothing to say about it. Target identity is
    /// the normalized fully qualified owner name plus the member name -- never
    /// `CodeUnit` equality across the language seam.
    ///
    /// `receiver_owner_fq_names` is the exact-owner set in phase 1
    /// (`spec.receiver_owner_fq_names`); the analysis layer widens it with
    /// visible descendants for subtype receivers.
    pub fn build_foreign_jvm(
        spec: &java_resolver::TargetSpec,
        java: &dyn JavaSource,
        receiver_owner_fq_names: &HashSet<String>,
    ) -> Self {
        let mut static_callable_arities = HashSet::default();
        let mut instance_callable_arities = HashSet::default();
        let mut has_static_field = false;
        let mut has_instance_field = false;
        let mut targets: Vec<CodeUnit> = spec.targets.iter().cloned().collect();
        targets.sort();
        for target in &targets {
            // Type targets skip metadata: their unit may belong to another JVM
            // language (Kotlin types arrive here too), and they have no
            // callable or field staticness to record.
            if spec.kind == java_resolver::TargetKind::Type {
                break;
            }
            let metadata = java.signature_metadata(target);
            let is_static = metadata.first().is_some_and(|metadata| {
                metadata.callable_is_static() || metadata.field_is_static()
            });
            match spec.kind {
                java_resolver::TargetKind::Method | java_resolver::TargetKind::Constructor => {
                    let arity = java_callable_arity(java, target);
                    if is_static {
                        static_callable_arities.insert(arity);
                    } else {
                        instance_callable_arities.insert(arity);
                    }
                }
                java_resolver::TargetKind::Field => {
                    has_static_field |= is_static;
                    has_instance_field |= !is_static;
                }
                java_resolver::TargetKind::Type => {}
            }
        }
        let foreign_spec = ForeignJvmMemberSpec {
            kind: spec.kind,
            member_name: spec.member_name.clone(),
            static_callable_arities,
            instance_callable_arities,
            has_static_field,
            has_instance_field,
        };
        let mut foreign_members: HashMap<(String, String), Vec<usize>> = HashMap::default();
        for owner_fqn in receiver_owner_fq_names {
            foreign_members.insert(
                (
                    scala_normalized_fq_name(owner_fqn),
                    spec.member_name.clone(),
                ),
                vec![0],
            );
        }
        let mut foreign_types: HashMap<String, Vec<usize>> = HashMap::default();
        let mut explicit_imports: HashMap<String, Vec<usize>> = HashMap::default();
        let mut owner_imports: HashMap<String, Vec<usize>> = HashMap::default();
        match spec.kind {
            java_resolver::TargetKind::Type => {
                let normalized = scala_normalized_fq_name(&spec.target.fq_name());
                foreign_types.insert(normalized.clone(), vec![0]);
                explicit_imports.insert(normalized.clone(), vec![0]);
                owner_imports.insert(normalized, vec![0]);
            }
            java_resolver::TargetKind::Constructor => {
                // `new Owner(..)` is a type reference to the owner; the arity
                // filter at the sink separates the constructor from the type.
                foreign_types.insert(scala_normalized_fq_name(&spec.owner.fq_name()), vec![0]);
            }
            java_resolver::TargetKind::Method | java_resolver::TargetKind::Field => {}
        }
        let kind = match spec.kind {
            java_resolver::TargetKind::Type => TargetKind::Type,
            java_resolver::TargetKind::Constructor => TargetKind::Constructor,
            java_resolver::TargetKind::Method => TargetKind::Method,
            java_resolver::TargetKind::Field => TargetKind::Field,
        };
        let scala_spec = TargetSpec {
            target: spec.target.clone(),
            kind,
            owner: Some(spec.owner.clone()),
            owner_name: Some(spec.owner.identifier().to_string()),
            family_owners: Vec::new(),
            receiver_owners: Vec::new(),
            member_name: spec.member_name.clone(),
            target_fq_name: scala_normalized_fq_name(&spec.target.fq_name()),
            owner_fq_name: Some(scala_normalized_fq_name(&spec.owner.fq_name())),
            arity: None,
            callable_alternatives: Default::default(),
            family_callable_alternatives: Default::default(),
            is_extension_method: false,
            accepts_field_implementation: false,
            is_object_type: false,
            accepts_apply_role: false,
            accepts_term_field_role: false,
            accepts_companion_apply_syntax: false,
        };
        Self {
            targets: vec![spec.target.clone()],
            specs: vec![scala_spec],
            exact: HashMap::default(),
            exact_owner_members: HashMap::default(),
            logical: HashMap::default(),
            explicit_imports,
            owner_imports,
            foreign_members,
            foreign_types,
            foreign_specs: vec![foreign_spec],
        }
    }

    fn target_ids(&self, target: &ScalaResolvedReference, role: ScalaReferenceRole) -> &[usize] {
        match target {
            ScalaResolvedReference::Exact(unit) => self
                .exact
                .get(&(unit.clone(), role))
                .map(Vec::as_slice)
                .unwrap_or_default(),
            ScalaResolvedReference::Logical(fqn) => self
                .logical
                .get(&(fqn.clone(), role))
                .or_else(|| {
                    // A foreign type target is keyed by normalized fqn and only
                    // ever carries the Type role (#1859).
                    (role == ScalaReferenceRole::Type)
                        .then(|| self.foreign_types.get(&scala_normalized_fq_name(fqn)))
                        .flatten()
                })
                .map(Vec::as_slice)
                .unwrap_or_default(),
        }
    }

    /// A catalog built for a foreign (Java/Kotlin) target family (#1859).
    fn is_foreign(&self) -> bool {
        !self.foreign_specs.is_empty()
    }

    pub fn relevant_names(&self) -> HashSet<String> {
        self.specs
            .iter()
            .flat_map(|spec| {
                [
                    Some(spec.member_name.clone()),
                    spec.owner_name.clone(),
                    companion_query_surface_name(spec),
                    Some(spec.target.identifier().to_string()),
                    // A constructor is also written `C.apply(..)`: the synthetic
                    // companion apply of a case class is this same declaration,
                    // so the scan must visit `apply` terminals for it.
                    (spec.kind == TargetKind::Constructor).then(|| "apply".to_string()),
                ]
            })
            .flatten()
            .collect()
    }
}

fn companion_query_surface_name(spec: &TargetSpec) -> Option<String> {
    if spec.kind != TargetKind::Method
        || !matches!(
            spec.member_name.as_str(),
            "apply" | "unapply" | "unapplySeq"
        )
    {
        return None;
    }
    let mut segments = brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path(
        Language::Scala,
        spec.target.short_name(),
    );
    let owner = segments
        .pop()
        .and_then(|member| {
            matches!(member.as_str(), "apply" | "unapply" | "unapplySeq").then_some(())
        })
        .and_then(|_| segments.pop())?;
    Some(owner.trim_end_matches('$').to_string())
}

fn exact_descendants_including_self(
    direct_descendants: &HashMap<CodeUnit, Vec<CodeUnit>>,
    owner: &CodeUnit,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<CodeUnit>, ScalaCatalogBuildError> {
    let mut descendants = Vec::new();
    let mut pending = vec![owner.clone()];
    let mut seen = HashSet::default();
    while let Some(current) = pending.pop() {
        ensure_catalog_active(cancellation)?;
        if !seen.insert(current.clone()) {
            continue;
        }
        if let Some(children) = direct_descendants.get(&current) {
            pending.extend(children.iter().cloned());
        }
        descendants.push(current);
    }
    Ok(descendants)
}

pub enum ScalaFileEligibility {
    All,
    Only(HashSet<usize>),
}

impl ScalaFileEligibility {
    fn allows(&self, target_id: usize) -> bool {
        matches!(self, Self::All)
            || matches!(self, Self::Only(targets) if targets.contains(&target_id))
    }
}

pub struct ScalaQueryHitSink<'a> {
    pub analyzer: &'a dyn ScalaWorkspaceSource,
    pub scala: &'a dyn ScalaSource,
    pub file: &'a ProjectFile,
    pub source: &'a str,
    pub class_ranges: ClassRangeIndex,
    pub line_starts: Vec<usize>,
    pub catalog: &'a ScalaQueryTargetCatalog,
    pub eligibility: &'a ScalaFileEligibility,
    pub hits: &'a mut [BTreeSet<UsageHit>],
    pub observed_hits: &'a mut BTreeSet<UsageHit>,
    /// Foreign-target scans (#1859) report receiver references they cannot
    /// type here instead of dropping them; Scala-target scans leave this
    /// `None` and keep dropping unproven names.
    pub unproven_hits: Option<&'a mut BTreeSet<UsageHit>>,
    pub enclosing_cache: HashMap<(usize, usize), Option<CodeUnit>>,
    pub relevant_names: HashSet<String>,
    pub allow_all_names: bool,
    pub max_usages: usize,
    pub limit_exceeded: bool,
}

impl ScalaQueryHitSink<'_> {
    /// True when the candidates for this target's normalized name form one
    /// replica family, so the reference belongs to the family and this target
    /// is a member of it (#2021). A cross-built symbol declared once per source
    /// set is one logical declaration with several physical homes, exactly as
    /// the forward direction already reports it; a candidate set that
    /// disagrees on any identity field is a genuine collision and keeps
    /// failing closed.
    ///
    /// Both candidate filters below are load-bearing and must survive: the
    /// first keeps a class and a method of the same name apart, the second
    /// keeps `class Foo` and `object Foo` (short name `Foo$`) apart even
    /// though both normalize to the same fully qualified name.
    fn target_is_logically_coherent(&self, target_id: usize) -> bool {
        let target = &self.catalog.targets[target_id];
        let target_is_singleton = target.is_class() && target.short_name().ends_with('$');
        // Same-file overloads are one physical declaration family split into
        // per-overload units (#1327), and cross-built replicas are one logical
        // declaration split across source sets (#2021); neither reads as a
        // collision.
        let declarations = self
            .analyzer
            .definitions_by_normalized_fqn(&scala_normalized_fq_name(&target.fq_name()));
        let mut candidates = declarations
            .iter()
            .filter(|candidate| candidate.kind() == target.kind())
            .filter(|candidate| {
                !target.is_class() || (candidate.short_name().ends_with('$') == target_is_singleton)
            })
            .peekable();
        candidates.peek().is_some() && single_replica_family(candidates)
    }

    fn wildcard_import_owner_target_ids(
        &mut self,
        import: &ImportInfo,
        active_package: &str,
        name: &str,
    ) -> Vec<usize> {
        let Some(structured_path) = import.path.as_ref() else {
            return Vec::new();
        };

        let mut owner_scopes = Vec::new();
        let mut current = self
            .class_ranges
            .enclosing_unit(structured_path.declaration_start_byte)
            .cloned();
        while let Some(owner) = current {
            current = self.scala.structural_parent_of(&owner);
            if owner.is_class() {
                owner_scopes.push(owner.fq_name());
            }
        }

        let mut selected = Vec::new();
        for end_index in (0..structured_path.segments.len())
            .filter(|index| structured_path.segments[*index] == name)
        {
            let segments = &structured_path.segments[..=end_index];
            let mut owner_matches = Vec::new();
            let mut owner_ambiguous = false;
            'owners: for owner in &owner_scopes {
                let owner_candidates = scala_nested_type_candidates(
                    owner.trim_end_matches('$').to_string(),
                    segments,
                    true,
                );
                let matches = self.explicit_import_candidate_target_ids(owner_candidates);
                if matches.is_empty() {
                    continue;
                }
                owner_ambiguous = matches.len() > 1;
                owner_matches = matches.into_iter().next().unwrap_or_default();
                break 'owners;
            }
            if owner_ambiguous {
                continue;
            }
            if !owner_matches.is_empty() {
                selected.extend(owner_matches);
                continue;
            }

            let package_matches = self.explicit_import_candidate_target_ids(
                import_candidate_fq_names(&segments.join("."), active_package),
            );
            if package_matches.len() == 1 {
                selected.extend(package_matches.into_iter().next().unwrap_or_default());
            }
        }

        selected.sort_unstable();
        selected.dedup();
        selected
    }

    fn explicit_import_candidate_target_ids(
        &self,
        candidates: impl IntoIterator<Item = String>,
    ) -> Vec<Vec<usize>> {
        let mut matches = Vec::new();
        for candidate in candidates {
            let Some(target_ids) = self
                .catalog
                .owner_imports
                .get(&scala_normalized_fq_name(&candidate))
            else {
                continue;
            };
            let coherent_target_ids = target_ids
                .iter()
                .copied()
                .filter(|target_id| self.target_is_logically_coherent(*target_id))
                .collect::<Vec<_>>();
            if !coherent_target_ids.is_empty()
                && !matches
                    .iter()
                    .any(|existing| existing == &coherent_target_ids)
            {
                matches.push(coherent_target_ids);
            }
        }
        matches
    }

    /// The hit snippet. Scala-target queries answer with the single trimmed
    /// line; foreign JVM targets follow the Java extractor's convention of a
    /// few lines of context (#1859), which the Java usage surfaces and tests
    /// are written against.
    fn hit_snippet(&self, line: usize) -> String {
        if self.catalog.is_foreign() {
            snippet_around_line(self.source, &self.line_starts, line, SNIPPET_CONTEXT_LINES)
        } else {
            query_snippet(self.source, &self.line_starts, line)
        }
    }

    /// The foreign type/constructor rules applied to ids a `Logical` type
    /// event matched (#1859): a type target accepts any reference to the type,
    /// a constructor target only a `new` whose single argument list the Java
    /// arity family accepts. Scala ids pass through untouched.
    fn filter_foreign_type_ids(
        &self,
        target_ids: &[usize],
        call_shape: Option<&ScalaCallSiteShape>,
    ) -> Vec<usize> {
        target_ids
            .iter()
            .copied()
            .filter(|target_id| {
                let Some(spec) = self.catalog.foreign_specs.get(*target_id) else {
                    return true;
                };
                match spec.kind {
                    java_resolver::TargetKind::Type => true,
                    java_resolver::TargetKind::Constructor => {
                        let Some(shape) = call_shape else {
                            return false;
                        };
                        if shape.type_arguments_only || shape.lists.len() != 1 {
                            return false;
                        }
                        let actual = shape.lists[0].arity;
                        spec.instance_callable_arities
                            .iter()
                            .chain(&spec.static_callable_arities)
                            .any(|expected| expected.accepts(actual))
                    }
                    java_resolver::TargetKind::Method | java_resolver::TargetKind::Field => {
                        debug_assert!(false, "member kinds never populate the foreign type bucket");
                        false
                    }
                }
            })
            .collect()
    }

    fn record_target_ids(
        &mut self,
        target_ids: &[usize],
        hit_kind: UsageHitKind,
        start: usize,
        end: usize,
    ) {
        if target_ids.is_empty() {
            return;
        }
        let enclosing = self
            .enclosing_cache
            .entry((start, end))
            .or_insert_with(|| {
                self.analyzer.enclosing_code_unit(
                    self.file,
                    &Range {
                        start_byte: start,
                        end_byte: end,
                        start_line: 0,
                        end_line: 0,
                    },
                )
            })
            .clone();
        // The retired duplicate scanner attributed a top-level site (an
        // import line has no enclosing unit) to the file's first declaration;
        // keep that convention for foreign catalogs only, so the Scala query
        // contract is untouched (#1859).
        let enclosing = enclosing.or_else(|| {
            self.catalog
                .is_foreign()
                .then(|| self.scala.declarations(self.file).into_iter().next())
                .flatten()
        });
        let Some(enclosing) = enclosing else {
            return;
        };
        let line = find_line_index_for_offset(&self.line_starts, start);
        let mut hit = usage_hit(
            self.file,
            line,
            start,
            end,
            enclosing.clone(),
            self.hit_snippet(line),
        );
        hit.kind = hit_kind;
        for target_id in target_ids.iter().copied() {
            if !self.eligibility.allows(target_id) {
                continue;
            }
            let query_target = &self.catalog.targets[target_id];
            // A reference inside a *callable* target's own declaration is a
            // recursive call (#1638). It is recorded as a `SelfReceiver` hit,
            // which the editor surface lists and the external usage surface
            // omits, and it stays out of `observed_hits` so the callsite budget
            // still counts only references from elsewhere. Inside any other
            // target's own declaration the site is the declaration itself, not
            // a use of it, and stays dropped.
            let inside_own_declaration = enclosing == *query_target
                && self
                    .analyzer
                    .ranges(query_target)
                    .iter()
                    .any(|range| range.start_byte <= start && end <= range.end_byte);
            let recursive = inside_own_declaration && query_target.is_function();
            if inside_own_declaration && !recursive {
                continue;
            }
            let target_hit = if recursive {
                hit.clone().into_self_receiver()
            } else {
                hit.clone()
            };
            if self.hits[target_id].insert(target_hit.clone()) && !recursive {
                self.observed_hits.insert(target_hit);
                if external_usage_hit_count(self.observed_hits) > self.max_usages {
                    self.limit_exceeded = true;
                    break;
                }
            }
        }
    }
}

impl ScalaReferenceSink for ScalaQueryHitSink<'_> {
    fn may_match_name(&self, name: &str) -> bool {
        self.allow_all_names || self.relevant_names.contains(name)
    }

    fn register_imports(&mut self, imports: &[ImportInfo]) {
        for import in imports {
            self.allow_all_names |= import.is_wildcard;
            if let Some(identifier) = import.identifier.as_deref() {
                self.relevant_names.insert(identifier.to_string());
            }
        }
    }

    fn record(
        &mut self,
        target: ScalaResolvedReference,
        role: ScalaReferenceRole,
        _reference_kind: UsageReferenceKind,
        hit_kind: UsageHitKind,
        start: usize,
        end: usize,
    ) {
        let target_ids = self.catalog.target_ids(&target, role);
        if self.catalog.is_foreign() {
            // A shapeless reference can name a foreign type but never one of
            // its constructors.
            let target_ids = self.filter_foreign_type_ids(target_ids, None);
            self.record_target_ids(&target_ids, hit_kind, start, end);
        } else {
            self.record_target_ids(target_ids, hit_kind, start, end);
        }
    }

    fn record_callable(
        &mut self,
        target: ScalaResolvedReference,
        role: ScalaReferenceRole,
        call_shape: &ScalaCallSiteShape,
        _reference_kind: UsageReferenceKind,
        hit_kind: UsageHitKind,
        start: usize,
        end: usize,
    ) {
        // An event for the queried physical callable has already passed the
        // scanner's structured owner, overload, inheritance, extension, and
        // complete call-shape resolution. Reapplying the query target's
        // flattened shape loses contextual and placeholder method values.
        // Exact descendant/override projections still need the secondary
        // target filter: their event unit differs from the queried ancestor,
        // and one physical override CodeUnit can represent several shapes.
        let raw_target_ids = self.catalog.target_ids(&target, role);
        let target_ids = raw_target_ids
            .iter()
            .copied()
            .filter(|target_id| {
                let spec = &self.catalog.specs[*target_id];
                if spec.kind != TargetKind::Method || spec.callable_alternatives.is_empty() {
                    return true;
                }
                let candidate_count = spec
                    .family_callable_alternatives
                    .iter()
                    .filter(|alternative| {
                        (!spec.is_extension_method || alternative.extension_receiver_type.is_some())
                            && callable_alternative_is_candidate(
                                alternative,
                                call_shape,
                                ScalaCallableSiteRole::Ordinary,
                            )
                    })
                    .count();
                spec.callable_alternatives.iter().any(|alternative| {
                    (!spec.is_extension_method || alternative.extension_receiver_type.is_some())
                        && !callable_alternative_contradicts_literal_arguments(
                            alternative,
                            call_shape,
                        )
                        && callable_alternative_matches(
                            alternative,
                            Some(call_shape),
                            ScalaCallableSiteRole::Ordinary,
                            candidate_count == 1,
                        )
                })
            })
            .collect::<Vec<_>>();
        if self.catalog.is_foreign() {
            // The foreign constructor rule replaces the Scala overload filter:
            // Java's arity family is the whole selection (#1859).
            let target_ids = self.filter_foreign_type_ids(&target_ids, Some(call_shape));
            self.record_target_ids(&target_ids, hit_kind, start, end);
            return;
        }
        self.record_target_ids(&target_ids, hit_kind, start, end);
    }

    fn record_exact_owner_member(
        &mut self,
        owner: CodeUnit,
        member: &str,
        role: ScalaReferenceRole,
        _reference_kind: UsageReferenceKind,
        hit_kind: UsageHitKind,
        start: usize,
        end: usize,
    ) {
        let target_ids = self
            .catalog
            .exact_owner_members
            .get(&(owner, member.to_string(), role))
            .map(Vec::as_slice)
            .unwrap_or_default();
        self.record_target_ids(target_ids, hit_kind, start, end);
    }

    fn record_logical_owner_member(
        &mut self,
        event: ScalaLogicalOwnerMember<'_>,
        _reference_kind: UsageReferenceKind,
        hit_kind: UsageHitKind,
        start: usize,
        end: usize,
    ) {
        let key = (
            scala_normalized_fq_name(event.owner_fqn),
            event.member.to_string(),
        );
        let Some(target_ids) = self.catalog.foreign_members.get(&key) else {
            return;
        };
        let target_ids = target_ids
            .iter()
            .copied()
            .filter(|target_id| {
                self.catalog.foreign_specs[*target_id].accepts(
                    event.receiver,
                    event.role,
                    event.call_shape,
                )
            })
            .collect::<Vec<_>>();
        self.record_target_ids(&target_ids, hit_kind, start, end);
    }

    fn record_unproven_name(&mut self, name: &str, start: usize, end: usize) {
        if !self
            .catalog
            .foreign_specs
            .iter()
            .any(|spec| spec.member_name == name)
        {
            return;
        }
        let enclosing = self
            .enclosing_cache
            .entry((start, end))
            .or_insert_with(|| {
                self.analyzer.enclosing_code_unit(
                    self.file,
                    &Range {
                        start_byte: start,
                        end_byte: end,
                        start_line: 0,
                        end_line: 0,
                    },
                )
            })
            .clone();
        let enclosing = enclosing.or_else(|| {
            self.catalog
                .is_foreign()
                .then(|| self.scala.declarations(self.file).into_iter().next())
                .flatten()
        });
        let Some(enclosing) = enclosing else {
            return;
        };
        let line = find_line_index_for_offset(&self.line_starts, start);
        let snippet = self.hit_snippet(line);
        let hit = usage_hit(self.file, line, start, end, enclosing, snippet).into_unproven();
        let Some(unproven_hits) = self.unproven_hits.as_deref_mut() else {
            return;
        };
        unproven_hits.insert(hit);
    }

    fn should_stop(&self) -> bool {
        self.limit_exceeded
    }

    fn record_import_name(
        &mut self,
        imports: &[ImportInfo],
        active_package: &str,
        name: &str,
        start: usize,
        end: usize,
    ) {
        let mut matches = Vec::new();
        for import in imports {
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            if import.is_wildcard {
                matches.extend(self.wildcard_import_owner_target_ids(import, active_package, name));
                continue;
            }
            let candidates = import_candidate_fq_names(&path, active_package);
            // `ImportInfo::local_name` is the shared `alias ?? identifier ??
            // tail-of-structured-path` desugar; scala's `identifier` is already
            // alias-resolved at construction, so this agrees with the old
            // `identifier ?? terminal-of(path)` fallback exactly.
            let local_name = import.local_name();
            let original_name = scala_short_name_terminal_segment(&path);
            if Some(name) != local_name && name != original_name {
                continue;
            }
            for candidate in candidates {
                if let Some(target_ids) = self
                    .catalog
                    .explicit_imports
                    .get(&scala_normalized_fq_name(&candidate))
                {
                    self.relevant_names.insert(name.to_string());
                    matches.extend(
                        target_ids
                            .iter()
                            .copied()
                            .filter(|target_id| self.target_is_logically_coherent(*target_id)),
                    );
                }
            }
        }
        matches.sort_unstable();
        matches.dedup();
        for target_id in matches {
            if !self.eligibility.allows(target_id) {
                continue;
            }
            if self.catalog.is_foreign() {
                // The import maps already keyed the target by its normalized
                // fqn; re-resolving through an `Exact` event would compare
                // `CodeUnit`s across the language seam and never match (#1859).
                // The retired duplicate scanner recorded import sites as
                // ordinary references, and the external usage surface excludes
                // `Import`-kind hits -- keep the site visible with `Reference`.
                self.record_target_ids(&[target_id], UsageHitKind::Reference, start, end);
                continue;
            }
            let kind = self.catalog.specs[target_id].kind;
            let role = match kind {
                TargetKind::Type => ScalaReferenceRole::Type,
                TargetKind::Constructor | TargetKind::Method => ScalaReferenceRole::Callable,
                TargetKind::Field => ScalaReferenceRole::Field,
            };
            let target = self.catalog.targets[target_id].clone();
            self.record(
                ScalaResolvedReference::Exact(target),
                role,
                UsageReferenceKind::Other,
                UsageHitKind::Import,
                start,
                end,
            );
        }
    }
}

fn query_snippet(source: &str, line_starts: &[usize], line: usize) -> String {
    let start = line_starts.get(line).copied().unwrap_or_default();
    let end = line_starts
        .get(line + 1)
        .copied()
        .unwrap_or(source.len())
        .min(source.len());
    source[start..end].trim().to_string()
}
