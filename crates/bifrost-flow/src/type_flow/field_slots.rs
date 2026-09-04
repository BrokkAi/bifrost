//! Workspace-wide syntactic summaries for class-owned instance fields.

use std::path::Path;

use crate::analyzer::semantic::{
    ClassAtom, ClassIdentity, ClassSeed, DynamicFieldWrite, LengthDelimitedDigest,
    MemberAccessQuery, MemoryLocationKind, ProcedureHandle, SemanticBudget, SemanticBudgetExceeded,
    SemanticEffect, SemanticRequest, SemanticValueKind, SourceSpan, StableDigest, TypeFlowAdapter,
    UnknownReason, ValueFlowKind,
};
use crate::analyzer::{ProjectFile, WorkspaceAnalyzer};
use crate::hash::{HashMap, HashSet};

use super::plan::{SourceSite, SourceSiteKind, TypeFlowPlanError};

type FieldSlotKey = (ClassIdentity, Box<str>);
type FieldSlotAtom = (ClassAtom, SourceSite);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSlot {
    pub class: ClassIdentity,
    pub member: Box<str>,
    pub atoms: Vec<(ClassAtom, SourceSite)>,
}

#[derive(Debug, Clone)]
pub struct FieldSlotIndex {
    slots: Vec<FieldSlot>,
    lookup: HashMap<ClassIdentity, HashMap<Box<str>, usize>>,
    digest: StableDigest,
    semantic_budget_exhaustion: Option<SemanticBudgetExceeded>,
}

#[derive(Default)]
struct CollectedSlots {
    stores: HashMap<FieldSlotKey, Vec<FieldSlotAtom>>,
    loads: HashMap<FieldSlotKey, SourceSite>,
    foreign_members: HashSet<Box<str>>,
    dynamic_members: HashSet<Box<str>>,
    dynamic_any: bool,
    globally_incomplete: bool,
    semantic_budget_exhaustion: Option<SemanticBudgetExceeded>,
}

impl FieldSlotIndex {
    pub fn build(
        workspace: &WorkspaceAnalyzer,
        adapter: &dyn TypeFlowAdapter,
        semantic_budget: &mut SemanticBudget,
        cancellation: &crate::analyzer::semantic::CancellationToken,
    ) -> Result<Self, TypeFlowPlanError> {
        let files = workspace
            .analyzer()
            .project()
            .analyzable_files(adapter.language())
            .map_err(TypeFlowPlanError::WorkspaceEnumeration)?;
        let mut collected = CollectedSlots::default();
        for file in files {
            if cancellation.is_cancelled() {
                return Err(TypeFlowPlanError::Cancelled);
            }
            let outcome = workspace
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(semantic_budget, cancellation),
                )
                .map_err(TypeFlowPlanError::Discovery)?;
            collected.globally_incomplete |= !outcome.is_complete();
            if collected.semantic_budget_exhaustion.is_none() {
                collected.semantic_budget_exhaustion = outcome.budget_exceeded();
            }
            let Some(artifact) = outcome.available_value() else {
                continue;
            };
            for procedure in artifact.procedures() {
                let procedure = artifact
                    .procedure_handle(procedure.id())
                    .expect("a retained artifact owns each procedure");
                collect_procedure(workspace, adapter, &procedure, &mut collected);
            }
        }
        Ok(Self::finish(workspace, adapter, collected))
    }

    fn finish(
        workspace: &WorkspaceAnalyzer,
        adapter: &dyn TypeFlowAdapter,
        collected: CollectedSlots,
    ) -> Self {
        let mut requested = collected.loads.keys().cloned().collect::<Vec<_>>();
        requested.sort_by(|(left_class, left_member), (right_class, right_member)| {
            class_order(left_class, right_class).then_with(|| left_member.cmp(right_member))
        });
        let mut hierarchy_cache = HashMap::default();
        let mut slots = Vec::new();
        for (class, member) in requested {
            let hierarchy = hierarchy_cache
                .entry(class.clone())
                .or_insert_with(|| adapter.class_hierarchy(workspace, &class))
                .clone();
            let mut related = vec![class.clone()];
            related.extend(hierarchy.ancestors.iter().cloned());
            if let Some(descendants) = &hierarchy.descendants {
                related.extend(descendants.iter().cloned());
            }
            related.sort_by(class_order);
            related.dedup();

            let mut atoms = Vec::new();
            let mut incomplete = collected.globally_incomplete
                || hierarchy.descendants.is_none()
                || hierarchy.unresolved_base
                || hierarchy.dynamic_attributes
                || collected.dynamic_any
                || collected.foreign_members.contains(member.as_ref())
                || collected.dynamic_members.contains(member.as_ref());
            for owner in &related {
                let owner_hierarchy = hierarchy_cache
                    .entry(owner.clone())
                    .or_insert_with(|| adapter.class_hierarchy(workspace, owner));
                if matches!(owner, ClassIdentity::External { .. })
                    || owner_hierarchy.descendants.is_none()
                    || owner_hierarchy.unresolved_base
                    || owner_hierarchy.dynamic_attributes
                    || !adapter.field_slot_is_complete(workspace, owner, &member)
                {
                    incomplete = true;
                }
                if let Some(stored) = collected.stores.get(&(owner.clone(), member.clone())) {
                    atoms.extend(stored.iter().cloned());
                }
            }
            dedup_atoms(&mut atoms);
            if incomplete {
                let site = collected
                    .loads
                    .get(&(class.clone(), member.clone()))
                    .expect("a requested slot retains a load site")
                    .clone();
                atoms.push((
                    ClassAtom::Unknown(UnknownReason::FieldSlotIncomplete),
                    SourceSite {
                        kind: SourceSiteKind::Unknown,
                        ..site
                    },
                ));
                dedup_atoms(&mut atoms);
            }
            if atoms.is_empty() {
                continue;
            }
            slots.push(FieldSlot {
                class,
                member,
                atoms,
            });
        }
        let digest = digest_slots(&slots);
        let mut lookup: HashMap<ClassIdentity, HashMap<Box<str>, usize>> = HashMap::default();
        for (index, slot) in slots.iter().enumerate() {
            lookup
                .entry(slot.class.clone())
                .or_default()
                .insert(slot.member.clone(), index);
        }
        Self {
            slots,
            lookup,
            digest,
            semantic_budget_exhaustion: collected.semantic_budget_exhaustion,
        }
    }

    pub fn slot(&self, class: &ClassIdentity, member: &str) -> Option<&FieldSlot> {
        self.lookup
            .get(class)?
            .get(member)
            .map(|index| &self.slots[*index])
    }

    pub const fn digest(&self) -> StableDigest {
        self.digest
    }

    pub const fn semantic_budget_exhausted(&self) -> bool {
        self.semantic_budget_exhaustion.is_some()
    }

    pub const fn semantic_budget_exhaustion(&self) -> Option<SemanticBudgetExceeded> {
        self.semantic_budget_exhaustion
    }

    pub fn slots(&self) -> &[FieldSlot] {
        &self.slots
    }
}

fn collect_procedure(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    procedure: &ProcedureHandle,
    collected: &mut CollectedSlots,
) {
    for write in adapter.dynamic_field_writes(workspace, procedure) {
        match write {
            DynamicFieldWrite::Member(member) => {
                collected.dynamic_members.insert(member);
            }
            DynamicFieldWrite::Any => collected.dynamic_any = true,
        }
    }
    let semantics = procedure.semantics();
    let receiver_values = receiver_values(procedure);
    let enclosing_class = adapter.enclosing_class(workspace, procedure);
    let predecessors = value_predecessors(procedure);
    for point in semantics.points() {
        for event in &point.events {
            match event.effect {
                SemanticEffect::MemoryStore {
                    location, value, ..
                } => {
                    let location = semantics
                        .memory_location(location)
                        .expect("a memory-store location is retained");
                    let MemoryLocationKind::Field { base, .. } = location.kind else {
                        continue;
                    };
                    let Some(member) = adapter.accessed_member(
                        workspace,
                        procedure,
                        MemberAccessQuery::Load(location),
                    ) else {
                        collected.dynamic_any = true;
                        continue;
                    };
                    let Some(class) = enclosing_class
                        .clone()
                        .filter(|_| receiver_values.contains(&base))
                    else {
                        collected.foreign_members.insert(member);
                        continue;
                    };
                    let span = mapping_span(
                        procedure,
                        semantics
                            .value(value)
                            .expect("a stored value is retained")
                            .source,
                    );
                    let Some(file) = file_for_procedure(workspace, procedure) else {
                        collected.globally_incomplete = true;
                        continue;
                    };
                    let classified = classify_stored_value(
                        workspace,
                        adapter,
                        procedure,
                        value,
                        &predecessors,
                        file,
                        span,
                    );
                    collected
                        .stores
                        .entry((class, member))
                        .or_default()
                        .extend(classified);
                }
                SemanticEffect::MemoryLoad {
                    location, result, ..
                } => {
                    let location = semantics
                        .memory_location(location)
                        .expect("a memory-load location is retained");
                    let MemoryLocationKind::Field { base, .. } = location.kind else {
                        continue;
                    };
                    let Some(class) = enclosing_class
                        .clone()
                        .filter(|_| receiver_values.contains(&base))
                    else {
                        continue;
                    };
                    let Some(member) = adapter.accessed_member(
                        workspace,
                        procedure,
                        MemberAccessQuery::Load(location),
                    ) else {
                        continue;
                    };
                    let Some(file) = file_for_procedure(workspace, procedure) else {
                        collected.globally_incomplete = true;
                        continue;
                    };
                    let result = semantics.value(result).expect("a load result is retained");
                    let key = (class, member);
                    let site = SourceSite {
                        file,
                        span: mapping_span(procedure, result.source),
                        kind: SourceSiteKind::Unknown,
                    };
                    if collected
                        .loads
                        .get(&key)
                        .is_none_or(|existing| source_site_order(&site, existing).is_lt())
                    {
                        collected.loads.insert(key, site);
                    }
                }
                _ => {}
            }
        }
    }
}

pub(super) fn receiver_values(
    procedure: &ProcedureHandle,
) -> HashSet<crate::analyzer::semantic::ValueId> {
    let semantics = procedure.semantics();
    let mut values = semantics
        .values()
        .iter()
        .filter_map(|value| {
            matches!(value.kind, SemanticValueKind::Receiver { .. }).then_some(value.id)
        })
        .collect::<HashSet<_>>();
    loop {
        let before = values.len();
        for point in semantics.points() {
            for event in &point.events {
                if let SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Receiver,
                    source,
                    target,
                } = event.effect
                    && values.contains(&source)
                {
                    values.insert(target);
                }
            }
        }
        if values.len() == before {
            return values;
        }
    }
}

fn value_predecessors(
    procedure: &ProcedureHandle,
) -> HashMap<crate::analyzer::semantic::ValueId, Vec<crate::analyzer::semantic::ValueId>> {
    let mut predecessors: HashMap<_, Vec<_>> = HashMap::default();
    for point in procedure.semantics().points() {
        for event in &point.events {
            let pair = match event.effect {
                SemanticEffect::Assignment { target, value } => Some((target, value)),
                SemanticEffect::ValueFlow { source, target, .. } => Some((target, source)),
                _ => None,
            };
            if let Some((target, source)) = pair {
                let entries = predecessors.entry(target).or_default();
                if !entries.contains(&source) {
                    entries.push(source);
                }
            }
        }
    }
    predecessors
}

#[allow(clippy::too_many_arguments)]
fn classify_stored_value(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    procedure: &ProcedureHandle,
    value: crate::analyzer::semantic::ValueId,
    predecessors: &HashMap<
        crate::analyzer::semantic::ValueId,
        Vec<crate::analyzer::semantic::ValueId>,
    >,
    file: ProjectFile,
    span: SourceSpan,
) -> Vec<(ClassAtom, SourceSite)> {
    let semantics = procedure.semantics();
    let mut pending = vec![value];
    let mut seen = HashSet::default();
    let mut classified = Vec::new();
    let mut incomplete = false;
    while let Some(value) = pending.pop() {
        if !seen.insert(value) {
            incomplete = true;
            continue;
        }
        if let Some(call) = semantics
            .call_sites()
            .iter()
            .find(|call| call.result == Some(value) || call.normal_results.contains(&value))
        {
            match adapter.constructed_class(workspace, procedure, call) {
                ClassSeed::Class(class) => classified.push((
                    ClassAtom::Class(class),
                    SourceSite {
                        file: file.clone(),
                        span,
                        kind: SourceSiteKind::ConstructorCall,
                    },
                )),
                ClassSeed::Unknown(_) | ClassSeed::NotApplicable => incomplete = true,
            }
            continue;
        }
        if let Some(allocation) = semantics
            .allocations()
            .iter()
            .find(|allocation| allocation.result == value)
        {
            match adapter.allocation_class(workspace, procedure, allocation) {
                ClassSeed::Class(class) => classified.push((
                    ClassAtom::Class(class),
                    SourceSite {
                        file: file.clone(),
                        span,
                        kind: SourceSiteKind::ContainerLiteral,
                    },
                )),
                ClassSeed::Unknown(_) | ClassSeed::NotApplicable => incomplete = true,
            }
            continue;
        }
        let row = semantics
            .value(value)
            .expect("a predecessor value is retained");
        match &row.kind {
            SemanticValueKind::Constant => {
                match adapter.constant_class(workspace, procedure, row) {
                    ClassSeed::Class(class) => classified.push((
                        ClassAtom::Class(class),
                        SourceSite {
                            file: file.clone(),
                            span,
                            kind: SourceSiteKind::Literal,
                        },
                    )),
                    ClassSeed::Unknown(_) | ClassSeed::NotApplicable => incomplete = true,
                }
                continue;
            }
            SemanticValueKind::Parameter {
                ordinal,
                multiplicity,
                ..
            } => {
                if multiplicity.is_rest() {
                    incomplete = true;
                } else {
                    match adapter.declared_parameter_class(workspace, procedure, *ordinal) {
                        ClassSeed::Class(class) => classified.push((
                            ClassAtom::Class(class),
                            SourceSite {
                                file: file.clone(),
                                span,
                                kind: SourceSiteKind::DeclaredParameter,
                            },
                        )),
                        ClassSeed::Unknown(_) | ClassSeed::NotApplicable => incomplete = true,
                    }
                }
                continue;
            }
            _ => {}
        }
        match predecessors.get(&value) {
            Some(sources) if !sources.is_empty() => pending.extend(sources.iter().copied()),
            _ => incomplete = true,
        }
    }
    if incomplete || classified.is_empty() {
        classified.push((
            ClassAtom::Unknown(UnknownReason::FieldSlotIncomplete),
            SourceSite {
                file,
                span,
                kind: SourceSiteKind::Unknown,
            },
        ));
    }
    dedup_atoms(&mut classified);
    classified
}

fn mapping_span(
    procedure: &ProcedureHandle,
    source: crate::analyzer::semantic::SourceMappingId,
) -> SourceSpan {
    procedure
        .semantics()
        .source_mapping(source)
        .expect("a retained IR row's source mapping is live")
        .locator
        .anchor()
        .span()
}

fn file_for_procedure(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
) -> Option<ProjectFile> {
    workspace
        .analyzer()
        .project()
        .file_by_rel_path(Path::new(procedure.semantics().locator().path().as_str()))
}

fn class_order(left: &ClassIdentity, right: &ClassIdentity) -> std::cmp::Ordering {
    match (left, right) {
        (ClassIdentity::Workspace(left), ClassIdentity::Workspace(right)) => left.cmp(right),
        (ClassIdentity::Workspace(_), ClassIdentity::External { .. }) => std::cmp::Ordering::Less,
        (ClassIdentity::External { .. }, ClassIdentity::Workspace(_)) => {
            std::cmp::Ordering::Greater
        }
        (
            ClassIdentity::External {
                qualified_name: left_name,
                symbol_id: left_id,
            },
            ClassIdentity::External {
                qualified_name: right_name,
                symbol_id: right_id,
            },
        ) => left_name
            .cmp(right_name)
            .then_with(|| left_id.cmp(right_id)),
    }
}

fn atom_order(
    (left, left_site): &(ClassAtom, SourceSite),
    (right, right_site): &(ClassAtom, SourceSite),
) -> std::cmp::Ordering {
    let atom_order = match (left, right) {
        (ClassAtom::Class(left), ClassAtom::Class(right)) => class_order(left, right),
        (ClassAtom::Class(_), ClassAtom::Unknown(_)) => std::cmp::Ordering::Less,
        (ClassAtom::Unknown(_), ClassAtom::Class(_)) => std::cmp::Ordering::Greater,
        (ClassAtom::Unknown(left), ClassAtom::Unknown(right)) => left.label().cmp(right.label()),
    };
    atom_order.then_with(|| source_site_order(left_site, right_site))
}

fn source_site_order(left: &SourceSite, right: &SourceSite) -> std::cmp::Ordering {
    left.file
        .cmp(&right.file)
        .then_with(|| left.span.start_byte().cmp(&right.span.start_byte()))
        .then_with(|| left.span.end_byte().cmp(&right.span.end_byte()))
        .then_with(|| source_kind_label(left.kind).cmp(source_kind_label(right.kind)))
}

fn dedup_atoms(atoms: &mut Vec<(ClassAtom, SourceSite)>) {
    atoms.sort_by(atom_order);
    atoms.dedup();
}

fn digest_slots(slots: &[FieldSlot]) -> StableDigest {
    let mut digest = LengthDelimitedDigest::new(b"bifrost-type-flow-field-slots-v1");
    for slot in slots {
        push_class(&mut digest, &slot.class);
        digest.push(slot.member.as_bytes());
        for (atom, site) in &slot.atoms {
            match atom {
                ClassAtom::Class(class) => {
                    digest.push(b"class");
                    push_class(&mut digest, class);
                }
                ClassAtom::Unknown(reason) => {
                    digest.push(b"unknown");
                    digest.push(reason.label().as_bytes());
                }
            }
            digest.push(site.file.rel_path().to_string_lossy().as_bytes());
            digest.push(&site.span.start_byte().to_le_bytes());
            digest.push(&site.span.end_byte().to_le_bytes());
            digest.push(source_kind_label(site.kind).as_bytes());
        }
    }
    digest.finish()
}

fn push_class(digest: &mut LengthDelimitedDigest, class: &ClassIdentity) {
    match class {
        ClassIdentity::Workspace(unit) => {
            digest.push(b"workspace");
            digest.push(unit.fq_name_str().as_bytes());
            digest.push(unit.source().rel_path().to_string_lossy().as_bytes());
        }
        ClassIdentity::External {
            qualified_name,
            symbol_id,
        } => {
            digest.push(b"external");
            digest.push(qualified_name.as_bytes());
            digest.push(symbol_id.as_bytes());
        }
    }
}

const fn source_kind_label(kind: SourceSiteKind) -> &'static str {
    match kind {
        SourceSiteKind::ConstructorCall => "constructor_call",
        SourceSiteKind::Literal => "literal",
        SourceSiteKind::ContainerLiteral => "container_literal",
        SourceSiteKind::DeclaredParameter => "declared_parameter",
        SourceSiteKind::RootReceiver => "root_receiver",
        SourceSiteKind::Unknown => "unknown",
    }
}
