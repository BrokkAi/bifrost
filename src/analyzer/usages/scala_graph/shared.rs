use super::inverted::{
    self, ProjectTypes, ScalaReferenceRole, ScalaReferenceSink, ScalaResolvedReference,
    callable_alternative_is_candidate, callable_alternative_matches, scan_scala_query_file,
};
use super::resolver::{
    TargetKind, TargetSpec, import_candidate_fq_names, member_matches_target_kind,
    scala_normalized_fq_name,
};
use super::syntax::{ScalaCallSiteShape, ScalaCallableSiteRole};
use crate::analyzer::scala::scala_import_path;
use crate::analyzer::usages::common::language_for_file;
use crate::analyzer::usages::common::usage_hit;
use crate::analyzer::usages::inverted_edges::{UsageEdgeWeights, UsageEdges, UsageReferenceKind};
use crate::analyzer::usages::model::{FuzzyResult, UsageHit, UsageHitKind};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageEdgeResolver, UsageQueryResolver, UsageScanScope};
use crate::analyzer::{
    BulkFileStateSource, CodeUnit, IAnalyzer, Language, ProjectFile, ScalaAnalyzer,
    resolve_analyzer,
};
use crate::hash::HashMap;
use crate::hash::HashSet;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use std::collections::BTreeSet;

pub(super) struct ScalaEdgeGraph {
    pub(super) files: Vec<ProjectFile>,
    pub(super) types: ProjectTypes,
}

pub(crate) struct ScalaQueryResolver<'a> {
    scala: &'a ScalaAnalyzer,
}

struct ScalaQueryTargetCatalog {
    targets: Vec<CodeUnit>,
    specs: Vec<TargetSpec>,
    exact: HashMap<(CodeUnit, ScalaReferenceRole), Vec<usize>>,
    exact_owner_members: HashMap<(CodeUnit, String, ScalaReferenceRole), Vec<usize>>,
    logical: HashMap<(String, ScalaReferenceRole), Vec<usize>>,
    explicit_imports: HashMap<String, Vec<usize>>,
    wildcard_imports: HashMap<(String, String), Vec<usize>>,
}

enum ScalaCatalogBuildError {
    Cancelled,
    UnsupportedTarget(CodeUnit),
}

fn ensure_catalog_active(
    cancellation: Option<&crate::cancellation::CancellationToken>,
) -> Result<(), ScalaCatalogBuildError> {
    if cancellation.is_some_and(crate::cancellation::CancellationToken::is_cancelled) {
        Err(ScalaCatalogBuildError::Cancelled)
    } else {
        Ok(())
    }
}

impl ScalaQueryTargetCatalog {
    fn build(
        scala: &ScalaAnalyzer,
        targets: &[CodeUnit],
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> Result<Self, ScalaCatalogBuildError> {
        ensure_catalog_active(cancellation)?;
        let mut exact: HashMap<(CodeUnit, ScalaReferenceRole), Vec<usize>> = HashMap::default();
        let mut exact_owner_members: HashMap<(CodeUnit, String, ScalaReferenceRole), Vec<usize>> =
            HashMap::default();
        let mut explicit_imports: HashMap<String, Vec<usize>> = HashMap::default();
        let mut wildcard_imports: HashMap<(String, String), Vec<usize>> = HashMap::default();
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
                        if let Some(class) = scala
                            .project_types()
                            .exact_case_class_for_companion_apply(scala, target)
                        {
                            for constructor in scala.project_types().exact_member_declarations(
                                scala,
                                &class,
                                class.identifier(),
                            ) {
                                ensure_catalog_active(cancellation)?;
                                if constructor.is_function() && constructor.is_synthetic() {
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
                        }
                    }
                }
                TargetKind::Constructor => {}
            }
            explicit_imports
                .entry(scala_normalized_fq_name(&spec.target_fq_name))
                .or_default()
                .push(target_id);
            if let Some(owner_fq_name) = spec.owner_fq_name.as_ref() {
                explicit_imports
                    .entry(scala_normalized_fq_name(owner_fq_name))
                    .or_default()
                    .push(target_id);
                wildcard_imports
                    .entry((
                        scala_normalized_fq_name(owner_fq_name),
                        spec.member_name.clone(),
                    ))
                    .or_default()
                    .push(target_id);
            }
            wildcard_imports
                .entry((
                    scala_normalized_fq_name(spec.target.package_name()),
                    spec.member_name.clone(),
                ))
                .or_default()
                .push(target_id);
            if let Some(parent) = spec.type_parent.as_ref() {
                wildcard_imports
                    .entry((
                        scala_normalized_fq_name(&parent.fq_name()),
                        spec.member_name.clone(),
                    ))
                    .or_default()
                    .push(target_id);
            }
            if let (Some(owner), Some(owner_name)) = (spec.owner.as_ref(), spec.owner_name.as_ref())
            {
                wildcard_imports
                    .entry((
                        scala_normalized_fq_name(owner.package_name()),
                        owner_name.clone(),
                    ))
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
            .chain(wildcard_imports.values_mut())
        {
            ensure_catalog_active(cancellation)?;
            target_ids.sort_unstable();
            target_ids.dedup();
        }
        // The whole-graph scanner still has a few resolution paths whose
        // authoritative result is an FQN. They are safe for exact query
        // buckets only when the analyzer proves that FQN has one physical
        // declaration project-wide. In particular, uniqueness among the
        // requested targets is not enough: source replicas outside the request
        // must keep the reference ambiguous.
        let mut logical = HashMap::default();
        for ((unit, role), target_ids) in &exact {
            ensure_catalog_active(cancellation)?;
            let declarations = scala.definitions(&unit.fq_name()).collect::<Vec<_>>();
            if declarations.len() == 1 && declarations.first() == Some(unit) {
                logical.insert((unit.fq_name(), *role), target_ids.clone());
            }
        }

        Ok(Self {
            targets: targets.to_vec(),
            specs,
            exact,
            exact_owner_members,
            logical,
            explicit_imports,
            wildcard_imports,
        })
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
                .map(Vec::as_slice)
                .unwrap_or_default(),
        }
    }
}

fn exact_descendants_including_self(
    direct_descendants: &HashMap<CodeUnit, Vec<CodeUnit>>,
    owner: &CodeUnit,
    cancellation: Option<&crate::cancellation::CancellationToken>,
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

enum ScalaFileEligibility {
    All,
    Only(HashSet<usize>),
}

impl ScalaFileEligibility {
    fn allows(&self, target_id: usize) -> bool {
        matches!(self, Self::All)
            || matches!(self, Self::Only(targets) if targets.contains(&target_id))
    }
}

struct ScalaQueryHitSink<'a> {
    analyzer: &'a dyn IAnalyzer,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: Vec<usize>,
    catalog: &'a ScalaQueryTargetCatalog,
    eligibility: &'a ScalaFileEligibility,
    hits: &'a mut [BTreeSet<UsageHit>],
    observed_hits: &'a mut BTreeSet<UsageHit>,
    enclosing_cache: HashMap<(usize, usize), Option<CodeUnit>>,
    max_usages: usize,
    limit_exceeded: bool,
}

impl ScalaQueryHitSink<'_> {
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
                    &crate::analyzer::Range {
                        start_byte: start,
                        end_byte: end,
                        start_line: 0,
                        end_line: 0,
                    },
                )
            })
            .clone();
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
            query_snippet(self.source, &self.line_starts, line),
        );
        hit.kind = hit_kind;
        for target_id in target_ids.iter().copied() {
            if !self.eligibility.allows(target_id) {
                continue;
            }
            let query_target = &self.catalog.targets[target_id];
            if enclosing == *query_target
                && self
                    .analyzer
                    .ranges(query_target)
                    .iter()
                    .any(|range| range.start_byte <= start && end <= range.end_byte)
            {
                continue;
            }
            if self.hits[target_id].insert(hit.clone()) {
                self.observed_hits.insert(hit.clone());
                if self.observed_hits.len() > self.max_usages {
                    self.limit_exceeded = true;
                    break;
                }
            }
        }
    }
}

impl ScalaReferenceSink for ScalaQueryHitSink<'_> {
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
        self.record_target_ids(target_ids, hit_kind, start, end);
    }

    fn record_callable(
        &mut self,
        target: ScalaResolvedReference,
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
        let exact_target = match &target {
            ScalaResolvedReference::Exact(unit) => Some(unit),
            ScalaResolvedReference::Logical(_) => None,
        };
        let target_ids = self
            .catalog
            .target_ids(&target, ScalaReferenceRole::Callable)
            .iter()
            .copied()
            .filter(|target_id| {
                if exact_target.is_some_and(|unit| &self.catalog.targets[*target_id] == unit) {
                    return true;
                }
                let spec = &self.catalog.specs[*target_id];
                if spec.kind != TargetKind::Method || spec.callable_alternatives.is_empty() {
                    return true;
                }
                let candidate_count = spec
                    .callable_alternatives
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
                        && callable_alternative_matches(
                            alternative,
                            Some(call_shape),
                            ScalaCallableSiteRole::Ordinary,
                            candidate_count == 1,
                        )
                })
            })
            .collect::<Vec<_>>();
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

    fn should_stop(&self) -> bool {
        self.limit_exceeded
    }

    fn record_import_name(
        &mut self,
        imports: &[crate::analyzer::ImportInfo],
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
            let candidates = import_candidate_fq_names(&path, active_package);
            if import.is_wildcard {
                for candidate in candidates {
                    if let Some(target_ids) = self
                        .catalog
                        .wildcard_imports
                        .get(&(scala_normalized_fq_name(&candidate), name.to_string()))
                    {
                        matches.extend(target_ids.iter().copied());
                    }
                }
                continue;
            }
            let local_name = import
                .identifier
                .as_deref()
                .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(&path));
            if name != local_name {
                continue;
            }
            for candidate in candidates {
                if let Some(target_ids) = self
                    .catalog
                    .explicit_imports
                    .get(&scala_normalized_fq_name(&candidate))
                {
                    matches.extend(target_ids.iter().copied());
                }
            }
        }
        matches.sort_unstable();
        matches.dedup();
        for target_id in matches {
            if !self.eligibility.allows(target_id) {
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

impl<'a> UsageQueryResolver<'a> for ScalaQueryResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            scala: resolve_analyzer::<ScalaAnalyzer>(analyzer)?,
        })
    }

    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        if overloads.is_empty() {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        }

        let candidate_files = scan_scope.candidate_files();
        let scoped_files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| language_for_file(file) == Language::Scala)
            .cloned()
            .collect();
        let catalog = match ScalaQueryTargetCatalog::build(
            self.scala,
            overloads,
            scan_scope.cancellation(),
        ) {
            Ok(catalog) => catalog,
            Err(ScalaCatalogBuildError::Cancelled) => {
                return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
            }
            Err(ScalaCatalogBuildError::UnsupportedTarget(target)) => {
                return GraphUsageOutcome::fallback_safe(
                    target.fq_name(),
                    GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                    "ScalaUsageGraphStrategy",
                );
            }
        };
        let mut files: HashMap<ProjectFile, ScalaFileEligibility> = scoped_files
            .iter()
            .cloned()
            .map(|file| (file, ScalaFileEligibility::All))
            .collect();
        for (target_id, target) in overloads.iter().enumerate() {
            if scan_scope.allows(target.source()) && !scoped_files.contains(target.source()) {
                match files.entry(target.source().clone()) {
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(ScalaFileEligibility::Only(HashSet::from_iter([target_id])));
                    }
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        if let ScalaFileEligibility::Only(targets) = entry.get_mut() {
                            targets.insert(target_id);
                        }
                    }
                }
            }
        }
        let mut files = files.into_iter().collect::<Vec<_>>();
        files.sort_by(|(left, _), (right, _)| left.cmp(right));
        let mut hits = vec![BTreeSet::new(); overloads.len()];
        let mut observed_hits = BTreeSet::new();
        let mut limit_exceeded = false;
        for (file, eligibility) in &files {
            if scan_scope.is_cancelled() {
                break;
            }
            let Some(source) = analyzer.indexed_source(file) else {
                continue;
            };
            let mut sink = ScalaQueryHitSink {
                analyzer,
                file,
                source: &source,
                line_starts: compute_line_starts(&source),
                catalog: &catalog,
                eligibility,
                hits: &mut hits,
                observed_hits: &mut observed_hits,
                enclosing_cache: HashMap::default(),
                max_usages,
                limit_exceeded: false,
            };
            scan_scala_query_file(
                self.scala,
                analyzer,
                file,
                &source,
                &mut sink,
                scan_scope.cancellation(),
            );
            if sink.limit_exceeded {
                limit_exceeded = true;
                break;
            }
        }
        if limit_exceeded || observed_hits.len() > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: overloads[0].short_name().to_string(),
                total_callsites: observed_hits.len(),
                limit: max_usages,
                sample_hits: observed_hits,
            });
        }
        let hits_by_overload = overloads.iter().cloned().zip(hits).collect();

        GraphUsageOutcome::Resolved(FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload: HashMap::default(),
            unproven_total_by_overload: HashMap::default(),
        })
    }
}

pub(crate) struct ScalaEdgeResolver<'a> {
    scala: &'a ScalaAnalyzer,
    graph: ScalaEdgeGraph,
}

impl<'a> UsageEdgeResolver<'a> for ScalaEdgeResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let scala = resolve_analyzer::<ScalaAnalyzer>(analyzer)?;
        let files: Vec<ProjectFile> = analyzer
            .project()
            .analyzable_files(Language::Scala)
            .ok()?
            .into_iter()
            .collect();
        let file_states = scala.bulk_file_states(files.clone(), BulkFileStateSource::Include);
        let types = ProjectTypes::build_from_file_states(file_states);

        Some(Self {
            scala,
            graph: ScalaEdgeGraph { files, types },
        })
    }

    fn build_edges<F>(
        &self,
        _analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdges
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        inverted::build_scala_edges(self.scala, &self.graph, nodes, keep_file)
    }

    fn build_edge_weights<F>(
        &self,
        _analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdgeWeights
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        inverted::build_scala_edges(self.scala, &self.graph, nodes, keep_file)
    }
}
