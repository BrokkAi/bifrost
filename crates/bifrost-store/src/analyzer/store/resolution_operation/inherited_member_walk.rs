//! Query-local inherited member-type inventory. Integration slice S-I supplies
//! selected parent and inventory reads; this module never retains workspace data.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;
use std::sync::Arc;

use crate::analyzer::store::Result;

use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

use crate::analyzer::resolution::tier_evaluator::{
    InheritedFrontier, InheritedTierKnowledge, InheritedTierWitness,
};
use crate::analyzer::resolution::{
    ExternalOwnerIdentity, ResolutionLocalKey, SelectedResolutionMountOrdinal, SemanticId,
};

const OWNER_EXPANSION_LIMIT: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum BridgedDeclaration {
    Source {
        mount_ordinal: SelectedResolutionMountOrdinal,
        local_key: ResolutionLocalKey,
    },
    External(ExternalOwnerIdentity),
    Intrinsic(Arc<str>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MemberAccess {
    Public,
    Protected,
    PackagePrivate,
    Private,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MemberTypeCandidate {
    pub declaration: BridgedDeclaration,
    pub name: Arc<str>,
    pub access: MemberAccess,
    /// None when the declaring file's package could not be read.
    pub declaring_package: Option<Arc<str>>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct OwnerInventory {
    pub declared: Vec<MemberTypeCandidate>,
    /// None when the owner's package could not be read; only package-private
    /// inheritance depends on it.
    pub package: Option<Arc<str>>,
    pub complete: bool,
    pub frontiers: BTreeSet<&'static str>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct ParentInventory {
    pub definite: Vec<BridgedDeclaration>,
    pub frontiers: BTreeSet<&'static str>,
    pub complete: bool,
}

/// Reads selected facts and charges the borrowed session before returning rows.
/// A source owner is complete only with the TypeBody member-types claim, exhausted
/// member-owner pages and a complete declaration crosswalk. External and model
/// owners remain open until their current provider evidence exists.
pub(super) trait InheritedParentSource {
    fn direct_parents(
        &mut self,
        owner: &BridgedDeclaration,
        session: &ResolutionSession,
    ) -> Result<ParentInventory>;
}

pub(super) trait InheritedInventorySource {
    fn owner_inventory(
        &mut self,
        owner: &BridgedDeclaration,
        session: &ResolutionSession,
    ) -> Result<OwnerInventory>;

    /// The package `owner` is declared in; None when it cannot be read now.
    fn owner_package(
        &mut self,
        owner: &BridgedDeclaration,
        session: &ResolutionSession,
    ) -> Result<Option<Arc<str>>>;
}

/// Reads the named member inventory from the same retained level as its parent
/// reader. The name is fixed for the lifetime of one walk.
pub(super) struct ReopenedInheritedInventorySource<'a, 'store, 'project> {
    parent: &'a mut ReopenedInheritedParentSource<'store, 'project>,
    name: &'a str,
}

impl<'a, 'store, 'project> ReopenedInheritedInventorySource<'a, 'store, 'project> {
    pub fn new(
        parent: &'a mut ReopenedInheritedParentSource<'store, 'project>,
        name: &'a str,
    ) -> Self {
        Self { parent, name }
    }
}

impl InheritedParentSource for ReopenedInheritedInventorySource<'_, '_, '_> {
    fn direct_parents(
        &mut self,
        owner: &BridgedDeclaration,
        session: &ResolutionSession,
    ) -> Result<ParentInventory> {
        self.parent.direct_parents(owner, session)
    }
}

impl InheritedInventorySource for ReopenedInheritedInventorySource<'_, '_, '_> {
    fn owner_inventory(
        &mut self,
        owner: &BridgedDeclaration,
        session: &ResolutionSession,
    ) -> Result<OwnerInventory> {
        use crate::analyzer::resolution::{
            ResolutionCompletion, SelectedTypedFactSource, SemanticId, TypedFactPageVisitor,
            TypedFactRequest,
        };
        use brokk_bifrost_core::analyzer::resolution_facts::{
            MemberTypesCoverage, ResolutionMemberKind,
        };
        use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;

        let mut answer = OwnerInventory::default();
        if !session.observe_cancellation() {
            answer.frontiers.insert("inherited_session_stopped");
            return Ok(answer);
        }
        if !self.parent.binding_current() {
            answer.frontiers.insert("inherited_selection_stale");
            return Ok(answer);
        }
        let (mount_ordinal, local_key) = match owner {
            BridgedDeclaration::Source {
                mount_ordinal,
                local_key,
            } => (mount_ordinal, local_key),
            // An intrinsic root is closed for a spelling absent from its member
            // names, which cover nested types, fields and callables together; a
            // spelling present among them is untyped there, so it stays Open.
            BridgedDeclaration::Intrinsic(root) => {
                match brokk_bifrost_jvm::intrinsics::root_member_inventory(root) {
                    Some(members) if members.iter().any(|member| member.name == self.name) => {
                        answer
                            .frontiers
                            .insert("inherited_intrinsic_member_untyped");
                    }
                    Some(_) => answer.complete = true,
                    None => {
                        answer
                            .frontiers
                            .insert("inherited_intrinsic_inventory_missing");
                    }
                }
                return Ok(answer);
            }
            BridgedDeclaration::External(_) => {
                answer.frontiers.insert("inherited_external_inventory");
                return Ok(answer);
            }
        };
        let Some(key) = local_key.try_u32() else {
            answer
                .frontiers
                .insert("inherited_owner_key_unrepresentable");
            return Ok(answer);
        };
        let level = self.parent.level.as_ref().expect("binding checked");
        // Package-private member types are inherited only within one package
        // (JLS 8.5), so every owner carries the package its file declares,
        // when that can be read.
        let package = self.source_package(owner)?;
        answer.package = package.clone();
        let definition = SemanticId::local(mount_ordinal.get(), key);
        let typed = level.ready.typed_source();
        let mut claim = None;
        let scope = typed.visit_member_scope_pages_for_definitions(
            TypedFactRequest::new(&[definition]),
            &self.parent.cancellation,
            &mut TypedFactPageVisitor::new(&mut |page| {
                for row in page {
                    if row.row().definition() == definition {
                        claim = row.row().member_types();
                    }
                }
                Ok(true)
            }),
        )?;
        let members = typed.visit_member_owner_pages_for_owners(
            TypedFactRequest::new(&[definition]),
            &self.parent.cancellation,
            &mut TypedFactPageVisitor::new(&mut |page| {
                for row in page {
                    let member = row.row();
                    if member.owner_definition() != definition
                        || member.member_name() != self.name
                        || !matches!(
                            member.kind(),
                            ResolutionMemberKind::NestedType | ResolutionMemberKind::AssociatedType
                        )
                    {
                        continue;
                    }
                    let Some((ordinal, key)) = member
                        .definition()
                        .ordinal()
                        .zip(member.definition().local_key())
                    else {
                        answer.frontiers.insert("inherited_member_identity_open");
                        continue;
                    };
                    answer.declared.push(MemberTypeCandidate {
                        declaration: BridgedDeclaration::Source {
                            mount_ordinal: SelectedResolutionMountOrdinal::new(ordinal),
                            local_key: ResolutionLocalKey::new(i64::from(key)),
                        },
                        name: Arc::from(self.name),
                        access: MemberAccess::Unknown,
                        declaring_package: package.clone(),
                    });
                }
                Ok(true)
            }),
        )?;
        let mut member_ids: Vec<_> = answer
            .declared
            .iter()
            .filter_map(|candidate| {
                let BridgedDeclaration::Source {
                    mount_ordinal,
                    local_key,
                } = candidate.declaration
                else {
                    return None;
                };
                local_key
                    .try_u32()
                    .map(|key| SemanticId::local(mount_ordinal.get(), key))
            })
            .collect();
        member_ids.sort_unstable();
        member_ids.dedup();
        let mut visibilities = HashMap::new();
        let mut visibility_complete = true;
        for page_ids in
            member_ids.chunks(crate::analyzer::resolution::MAX_TYPED_FACT_REQUESTS_PER_BATCH)
        {
            let visibility = typed.visit_declaration_visibility_pages_for_definitions(
                TypedFactRequest::new(page_ids),
                &self.parent.cancellation,
                &mut TypedFactPageVisitor::new(&mut |page| {
                    for row in page {
                        let access = match row.row().visibility() {
                            DeclaredVisibility::Public => MemberAccess::Public,
                            DeclaredVisibility::Protected => MemberAccess::Protected,
                            DeclaredVisibility::PackagePrivate => MemberAccess::PackagePrivate,
                            DeclaredVisibility::Private => MemberAccess::Private,
                            _ => MemberAccess::Unknown,
                        };
                        visibilities.insert(row.row().definition(), access);
                    }
                    Ok(true)
                }),
            )?;
            visibility_complete &= visibility.is_exhausted()
                && visibility.evidence() == &ResolutionCompletion::Complete;
        }
        for candidate in &mut answer.declared {
            let BridgedDeclaration::Source {
                mount_ordinal,
                local_key,
            } = candidate.declaration
            else {
                continue;
            };
            let id = SemanticId::local(
                mount_ordinal.get(),
                local_key.try_u32().expect("source member key"),
            );
            candidate.access = visibilities
                .get(&id)
                .copied()
                .unwrap_or(MemberAccess::Unknown);
        }
        if !session.observe_cancellation() || scope.is_cancelled() || members.is_cancelled() {
            answer.frontiers.insert("inherited_session_stopped");
        } else if !scope.is_exhausted()
            || !members.is_exhausted()
            || !visibility_complete
            || scope.evidence() != &ResolutionCompletion::Complete
            || members.evidence() != &ResolutionCompletion::Complete
        {
            answer.frontiers.insert("inherited_inventory_read_open");
        }
        match claim {
            Some(MemberTypesCoverage::Complete) => {}
            Some(MemberTypesCoverage::Open(reason)) => {
                answer.frontiers.insert(reason.label());
            }
            None => {
                answer
                    .frontiers
                    .insert("inherited_member_type_coverage_unknown");
            }
        }
        if !self.parent.binding_current() {
            answer.frontiers.insert("inherited_selection_stale");
        }
        answer.complete = answer.frontiers.is_empty();
        Ok(answer)
    }

    fn owner_package(
        &mut self,
        owner: &BridgedDeclaration,
        session: &ResolutionSession,
    ) -> Result<Option<Arc<str>>> {
        if !session.observe_cancellation() || !self.parent.binding_current() {
            return Ok(None);
        }
        self.source_package(owner)
    }
}

impl ReopenedInheritedInventorySource<'_, '_, '_> {
    fn source_package(&self, owner: &BridgedDeclaration) -> Result<Option<Arc<str>>> {
        let (BridgedDeclaration::Source { mount_ordinal, .. }, Some(level)) =
            (owner, self.parent.level.as_ref())
        else {
            return Ok(None);
        };
        let mount = level.mount_table().mount_by_ordinal(*mount_ordinal)?;
        Ok(level
            .jvm_source_file_package(
                mount.semantic_language(),
                mount.persisted_relative_path(),
                &self.parent.cancellation,
            )?
            .map(|package| Arc::from(package.unwrap_or_default())))
    }
}

/// A retained, read-only level operation for one inherited walk depth.
/// It is reopened from the final selection and never publishes results.
pub(super) struct ReopenedInheritedParentSource<'store, 'project> {
    captured_input: super::CapturedSelectedResolutionInput<'project>,
    level: Option<Box<super::SelectedResolutionOperation<'store, 'project>>>,
    cancellation: crate::CancellationToken,
}

impl<'store, 'project> ReopenedInheritedParentSource<'store, 'project> {
    /// Reopen the final operation's captured selection for one level.
    /// `level_knowledge` is what the level operation's own decisions read: the
    /// witness function one level down, or none in fixtures that test this
    /// source alone.
    pub fn open(
        store: &'store crate::analyzer::store::AnalyzerStore,
        captured_input: super::CapturedSelectedResolutionInput<'project>,
        cancellation: &crate::CancellationToken,
        level_knowledge: Option<JvmInheritedKnowledge<'project>>,
    ) -> Result<Self> {
        use super::SelectedResolutionOperationOpenOutcome;
        let level = match store.open_selected_resolution_level_operation(
            captured_input.input(),
            cancellation,
            level_knowledge,
        )? {
            SelectedResolutionOperationOpenOutcome::Ready(level) => Some(level),
            SelectedResolutionOperationOpenOutcome::Unavailable(_)
            | SelectedResolutionOperationOpenOutcome::Stale(_)
            | SelectedResolutionOperationOpenOutcome::Cancelled => None,
        };
        let source = Self {
            captured_input,
            level,
            cancellation: cancellation.clone(),
        };
        if !source.binding_current() {
            return Ok(Self {
                level: None,
                ..source
            });
        }
        Ok(source)
    }

    fn binding_current(&self) -> bool {
        let Some(level) = &self.level else {
            return false;
        };
        let final_input = &self.captured_input;
        let level_input = level.worker_input();
        level_input.analysis_generation == final_input.analysis_generation
            && level_input.snapshots == final_input.snapshots
            && selection_current(final_input)
    }
}

/// The project has not moved since the selection was captured.
fn selection_current(input: &super::CapturedSelectedResolutionInput<'_>) -> bool {
    input.project.analysis_generation() == input.analysis_generation
}

/// The level whose witnesses the final operation's decisions read. Level d
/// resolves parents through a level d-1 operation; level 0 is `Bottom`.
const FINAL_LEVEL: usize = 4;

/// The inherited member-type knowledge one operation's JVM simple-type-name
/// decisions read. It is installed before any JVM context work and never
/// replaced, so every decision memo of the operation is bound to it.
///
/// The walk variant is a trait object bounded by the operation's input
/// lifetime, like the operation's macro frontier reads: its level operations
/// sit behind interior mutability, which would otherwise make the operation
/// invariant in its lifetimes.
pub(crate) enum JvmInheritedKnowledge<'input> {
    /// A fixed table, for fixtures.
    Frozen(Arc<InheritedTierKnowledge>),
    /// Level 0: every inherited tier is Open, which bounds the descent.
    Bottom,
    /// A walk was requested without read-reuse authority.
    Unavailable,
    /// Witnesses computed on demand through reopened level operations.
    Walk(Box<dyn InheritedWitnessSource + 'input>),
}

/// Inherited member-type witnesses computed on demand.
pub(crate) trait InheritedWitnessSource {
    /// The witness for `owner`'s inherited member types named `lookup`, which
    /// is spelled `spelling`. None means `call` was cancelled; nothing was
    /// recorded for it.
    fn witness(
        &self,
        owner: SemanticId,
        lookup: SemanticId,
        spelling: &str,
        call: &crate::CancellationToken,
    ) -> Result<Option<InheritedTierWitness>>;
}

impl JvmInheritedKnowledge<'_> {
    pub(super) fn witness(
        &self,
        owner: SemanticId,
        lookup: SemanticId,
        spelling: &str,
        call: &crate::CancellationToken,
    ) -> Result<Option<InheritedTierWitness>> {
        match self {
            Self::Unavailable => Err(super::missing_read_reuse_authority("JVM inherited member")),
            Self::Frozen(table) => Ok(Some(table.witness(owner, lookup))),
            Self::Bottom => Ok(Some(open_witness(
                BTreeSet::new(),
                BTreeSet::from(["inherited_level_bound"]),
            ))),
            Self::Walk(function) => function.witness(owner, lookup, spelling, call),
        }
    }
}

fn open_witness(
    frontiers: BTreeSet<&'static str>,
    reasons: BTreeSet<&'static str>,
) -> InheritedTierWitness {
    InheritedTierWitness::Open {
        frontier: frontiers
            .into_iter()
            .map(|reason| InheritedFrontier {
                owner: None,
                reason,
            })
            .collect(),
        reasons: reasons.into_iter().collect(),
    }
}

/// State one final operation's levels share: the one bounded walk session,
/// whose budgets every level's parent resolution charges, the operation's
/// cancellation, and the owner allowance of the current root question.
struct WalkShared {
    operation_cancellation: crate::CancellationToken,
    session: ResolutionSession,
    allowance: Rc<Cell<usize>>,
}

/// Inherited member-type witnesses for one level, computed on first ask and
/// memoized for the operation that owns this function. It keeps the store and
/// a copy of that operation's captured selection, never the operation itself,
/// so it does not borrow its owner.
pub(crate) struct WitnessFunction<'store, 'project> {
    level: usize,
    shared: Rc<WalkShared>,
    store: &'store crate::analyzer::store::AnalyzerStore,
    /// The owning operation's captured selection; every level reopens it.
    captured_input: super::CapturedSelectedResolutionInput<'project>,
    /// The level below, reopened on first need. A re-entered level is a design
    /// error, which this cell's borrow check turns into a panic.
    source: std::cell::RefCell<Option<ReopenedInheritedParentSource<'store, 'project>>>,
    memo: std::cell::RefCell<HashMap<(SemanticId, SemanticId), InheritedTierWitness>>,
    #[cfg(debug_assertions)]
    spellings: std::cell::RefCell<HashMap<SemanticId, Box<str>>>,
}

impl<'store: 'project, 'project> WitnessFunction<'store, 'project> {
    /// The final level's function for an operation over `captured_input`.
    /// `operation_cancellation` is the token that operation was opened with;
    /// the walk session observes it.
    pub(crate) fn new(
        store: &'store crate::analyzer::store::AnalyzerStore,
        captured_input: super::CapturedSelectedResolutionInput<'project>,
        operation_cancellation: crate::CancellationToken,
    ) -> Self {
        use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
        let session = ResolutionSession::bounded(
            ReceiverAnalysisBudget::default(),
            Some(&operation_cancellation),
        );
        Self::at_level(
            FINAL_LEVEL,
            Rc::new(WalkShared {
                operation_cancellation,
                session,
                allowance: Rc::new(Cell::new(OWNER_EXPANSION_LIMIT)),
            }),
            store,
            captured_input,
        )
    }

    fn at_level(
        level: usize,
        shared: Rc<WalkShared>,
        store: &'store crate::analyzer::store::AnalyzerStore,
        captured_input: super::CapturedSelectedResolutionInput<'project>,
    ) -> Self {
        Self {
            level,
            shared,
            store,
            captured_input,
            source: std::cell::RefCell::new(None),
            memo: std::cell::RefCell::new(HashMap::new()),
            #[cfg(debug_assertions)]
            spellings: std::cell::RefCell::new(HashMap::new()),
        }
    }

    /// What the next level's operation reads.
    fn below(&self) -> JvmInheritedKnowledge<'project> {
        match self.level - 1 {
            0 => JvmInheritedKnowledge::Bottom,
            level => JvmInheritedKnowledge::Walk(Box::new(Self::at_level(
                level,
                Rc::clone(&self.shared),
                self.store,
                self.captured_input.clone(),
            ))),
        }
    }
}

impl<'store: 'project, 'project> InheritedWitnessSource for WitnessFunction<'store, 'project> {
    fn witness(
        &self,
        owner: SemanticId,
        lookup: SemanticId,
        spelling: &str,
        call: &crate::CancellationToken,
    ) -> Result<Option<InheritedTierWitness>> {
        #[cfg(debug_assertions)]
        {
            let mut spellings = self.spellings.borrow_mut();
            let known = spellings
                .entry(lookup)
                .or_insert_with(|| Box::from(spelling));
            debug_assert_eq!(&**known, spelling, "one lookup has one spelling");
        }
        // A project that moved since the capture makes the walk stale now; the
        // memo is not served and nothing is recorded.
        if !selection_current(&self.captured_input) {
            return Ok(Some(open_witness(
                BTreeSet::from(["inherited_selection_stale"]),
                BTreeSet::new(),
            )));
        }
        if let Some(witness) = self.memo.borrow().get(&(owner, lookup)) {
            return Ok(Some(witness.clone()));
        }
        let (Some(ordinal), Some(key)) = (owner.ordinal(), owner.local_key()) else {
            return Ok(Some(open_witness(
                BTreeSet::from(["inherited_owner_not_source"]),
                BTreeSet::new(),
            )));
        };
        let start = BridgedDeclaration::Source {
            mount_ordinal: SelectedResolutionMountOrdinal::new(ordinal),
            local_key: ResolutionLocalKey::new(i64::from(key)),
        };
        // One root question owns one allowance; the levels it descends into
        // share it.
        if self.level == FINAL_LEVEL {
            self.shared.allowance.set(OWNER_EXPANSION_LIMIT);
        }
        let computed = self.shared.session.with_call_cancellation(call, || {
            let mut slot = self.source.borrow_mut();
            if slot.is_none() {
                *slot = Some(ReopenedInheritedParentSource::open(
                    self.store,
                    self.captured_input.clone(),
                    &self.shared.operation_cancellation,
                    Some(self.below()),
                )?);
            }
            let source = slot.as_mut().expect("level opened");
            // The same selection gives every level the same mounts, so the
            // level answers the owner's language; an unopened level answers
            // Open, for which the language does not matter.
            let language = match &source.level {
                Some(level) => Some(
                    level
                        .mount_table()
                        .mount_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?
                        .semantic_language(),
                ),
                None => None,
            };
            let answer = InheritedMemberWalk::with_shared_allowance(
                ReopenedInheritedInventorySource::new(source, spelling),
                Rc::clone(&self.shared.allowance),
            )
            .inherited(&start, &self.shared.session)?;
            Ok::<_, crate::analyzer::store::StoreError>((answer, language))
        });
        let (answer, language) = match computed {
            Ok(answer) => answer?,
            Err(brokk_bifrost_core::analyzer::usages::resolution_session::CallCancelled) => {
                // The levels below may hold partial work of the cancelled
                // call, so the final level drops them; the next live call
                // reopens them.
                if self.level == FINAL_LEVEL {
                    self.source.borrow_mut().take();
                }
                return Ok(None);
            }
        };
        let witness = walk_witness(&answer, language);
        self.memo
            .borrow_mut()
            .insert((owner, lookup), witness.clone());
        Ok(Some(witness))
    }
}

#[cfg(any(test, feature = "test-support"))]
impl<'store: 'input, 'input> super::SelectedResolutionOperation<'store, 'input> {
    #[doc(hidden)]
    pub fn jvm_inherited_witness_for_test(
        &self,
        owner: SemanticId,
        lookup: SemanticId,
        spelling: &str,
        cancellation: &crate::CancellationToken,
    ) -> Result<Option<InheritedTierWitness>> {
        self.jvm_inherited_witness(owner, lookup, spelling, cancellation)
    }
}

/// The witness a finished walk proves, under the owner's language rule.
fn walk_witness(
    answer: &WalkAnswer,
    language: Option<brokk_bifrost_core::analyzer::model::Language>,
) -> InheritedTierWitness {
    use brokk_bifrost_core::analyzer::model::Language;
    // Kotlin proves absence only for a superclass's nested classifiers; the
    // walk does not yet record which parent edges are superclasses, so every
    // Kotlin walk keeps the other forms' Open rule.
    let rule = match language {
        Some(Language::Java) => InheritedRule::Java,
        Some(Language::Scala) => InheritedRule::ScalaTypeMembersCovered,
        _ => InheritedRule::KotlinOther,
    };
    match answer.closure(rule) {
        WalkClosure::Absent => InheritedTierWitness::Absent,
        WalkClosure::Unique | WalkClosure::Ambiguous => {
            let mut declarations = Vec::with_capacity(answer.candidates.len());
            for candidate in answer.candidates.keys() {
                let BridgedDeclaration::Source {
                    mount_ordinal,
                    local_key,
                } = candidate
                else {
                    return open_witness(
                        BTreeSet::from(["inherited_candidate_not_source"]),
                        BTreeSet::new(),
                    );
                };
                let Some(key) = local_key.try_u32() else {
                    return open_witness(
                        BTreeSet::from(["inherited_owner_key_unrepresentable"]),
                        BTreeSet::new(),
                    );
                };
                declarations.push(SemanticId::local(mount_ordinal.get(), key));
            }
            declarations.sort_unstable();
            declarations.dedup();
            InheritedTierWitness::Proven(declarations)
        }
        WalkClosure::Open => open_witness(answer.frontiers.clone(), answer.reasons.clone()),
    }
}

impl<'input> super::SelectedResolutionOperation<'_, 'input> {
    /// Install the knowledge this operation's JVM decisions read, before any
    /// JVM context work, so every decision memo is bound to it.
    pub(crate) fn install_jvm_inherited_knowledge(
        &mut self,
        knowledge: JvmInheritedKnowledge<'input>,
    ) {
        assert!(
            self.jvm_inherited_tier_knowledge.is_none(),
            "an operation reads one inherited-tier knowledge"
        );
        assert!(
            self.jvm_file_contexts.borrow().is_empty()
                && self.jvm_context_preparations.is_empty()
                && self.jvm_on_demand_type_ranks.borrow().is_empty(),
            "inherited-tier knowledge is installed before any JVM context work"
        );
        self.jvm_inherited_tier_knowledge = Some(knowledge);
    }

    /// The inherited witness for one enclosing class and one simple name.
    /// None means `cancellation` stopped the asking call.
    pub(super) fn jvm_inherited_witness(
        &self,
        owner: SemanticId,
        lookup: SemanticId,
        spelling: &str,
        cancellation: &crate::CancellationToken,
    ) -> Result<Option<InheritedTierWitness>> {
        self.jvm_inherited_tier_knowledge
            .as_ref()
            .expect("callers read inherited tiers only with installed knowledge")
            .witness(owner, lookup, spelling, cancellation)
    }
}

impl InheritedParentSource for ReopenedInheritedParentSource<'_, '_> {
    fn direct_parents(
        &mut self,
        owner: &BridgedDeclaration,
        session: &ResolutionSession,
    ) -> Result<ParentInventory> {
        use super::jvm_context::JvmImportContext;
        use crate::analyzer::resolution::{
            SelectedFactOperationBlueprintConstruction, SelectedResolutionContextValidationOutcome,
            SemanticId,
        };
        let mut result = ParentInventory::default();
        if !session.observe_cancellation() {
            result.frontiers.insert("inherited_session_stopped");
            return Ok(result);
        }
        if !self.binding_current() {
            result.frontiers.insert("inherited_selection_stale");
            return Ok(result);
        }
        let Some(level) = &self.level else {
            unreachable!("binding checked");
        };
        let (mount_ordinal, local_key) = match owner {
            BridgedDeclaration::Source {
                mount_ordinal,
                local_key,
            } => (mount_ordinal, local_key),
            // A closed hierarchy root has no parent to walk: its member table
            // already includes what it inherits.
            BridgedDeclaration::Intrinsic(_) => {
                result.complete = true;
                return Ok(result);
            }
            BridgedDeclaration::External(_) => {
                result.frontiers.insert("inherited_external_parent");
                return Ok(result);
            }
        };
        let mount = level.mount_table().mount_by_ordinal(*mount_ordinal)?;
        let caller_path = mount.persisted_relative_path();
        let storage_language = mount.storage_language();
        let JvmImportContext::Ready {
            context,
            scoped_gaps,
            ..
        } = level.jvm_import_context(mount.semantic_language(), caller_path, &self.cancellation)?
        else {
            result.frontiers.insert("inherited_parent_context_open");
            return Ok(result);
        };
        let SelectedResolutionContextValidationOutcome::Ready(context) = level.prepare_context(
            *context,
            &self.cancellation,
            &super::SelectedResolutionContextMetrics,
        )?
        else {
            result.frontiers.insert("inherited_parent_context_open");
            return Ok(result);
        };
        let SelectedFactOperationBlueprintConstruction::Ready(blueprint) =
            level.ready.collect_blueprint(context, &self.cancellation)?
        else {
            result.frontiers.insert("inherited_parent_blueprint_open");
            return Ok(result);
        };
        let lexical = level.ready.lexical_source();
        let typed = level.ready.typed_source();
        let Some(key) = local_key.try_u32() else {
            result
                .frontiers
                .insert("inherited_owner_key_unrepresentable");
            return Ok(result);
        };
        let definition = SemanticId::local(mount_ordinal.get(), key);
        let answer = level.with_jvm_hierarchy_query(
            super::jvm_demand::JvmForwardOperationContext {
                storage_language,
                blueprint: &blueprint,
                caller_path,
                import_gaps: &scoped_gaps,
                lexical: &lexical,
                typed: &typed,
                cancellation: &self.cancellation,
                session,
            },
            |query| query.jvm_direct_supertype_answer(definition),
        )?;
        if answer.completion != crate::analyzer::resolution::ResolutionCompletion::Complete {
            result.frontiers.insert("inherited_parent_answer_open");
        }
        for parent in answer.parents {
            if parent.completion != crate::analyzer::resolution::ResolutionCompletion::Complete
                || parent.targets.len() != 1
            {
                result.frontiers.insert("inherited_unresolved_parent");
                continue;
            }
            let target = parent.targets[0];
            if let (Some(mount_ordinal), Some(local_key)) = (target.ordinal(), target.local_key()) {
                result.definite.push(BridgedDeclaration::Source {
                    mount_ordinal: SelectedResolutionMountOrdinal::new(mount_ordinal),
                    local_key: ResolutionLocalKey::new(i64::from(local_key)),
                });
            } else if let Some(identity) = level
                .ready
                .context_identities
                .external_owner_identity(target)
            {
                // The hierarchy answer names an implicit root only after the
                // selected source proved it absent, so the edge is the root's.
                match (identity.provider_id.as_ref() == "jvm-intrinsic")
                    .then(|| {
                        brokk_bifrost_jvm::intrinsics::intrinsic_root_owner(&identity.owner_fqn)
                    })
                    .flatten()
                {
                    Some(root) => result
                        .definite
                        .push(BridgedDeclaration::Intrinsic(Arc::from(root))),
                    None => {
                        result.definite.push(BridgedDeclaration::External(identity));
                        result.frontiers.insert("inherited_external_parent");
                    }
                }
            } else {
                result.frontiers.insert("inherited_unresolved_parent");
            }
        }
        if !session.observe_cancellation() {
            return Ok(ParentInventory {
                frontiers: BTreeSet::from(["inherited_session_stopped"]),
                ..ParentInventory::default()
            });
        }
        if !self.binding_current() {
            return Ok(ParentInventory {
                frontiers: BTreeSet::from(["inherited_selection_stale"]),
                ..ParentInventory::default()
            });
        }
        result.complete = result.frontiers.is_empty();
        Ok(result)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct WalkAnswer {
    pub candidates: BTreeMap<BridgedDeclaration, MemberTypeCandidate>,
    pub frontiers: BTreeSet<&'static str>,
    pub reasons: BTreeSet<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InheritedRule {
    Java,
    KotlinSuperclassNested,
    KotlinOther,
    ScalaTypeMembersCovered,
    ScalaUnknownCoverage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WalkClosure {
    Absent,
    Unique,
    Ambiguous,
    Open,
}

impl WalkAnswer {
    pub fn closure(&self, rule: InheritedRule) -> WalkClosure {
        if self.is_open() {
            return WalkClosure::Open;
        }
        if self.candidates.is_empty() {
            return match rule {
                InheritedRule::Java
                | InheritedRule::KotlinSuperclassNested
                | InheritedRule::ScalaTypeMembersCovered => WalkClosure::Absent,
                InheritedRule::KotlinOther | InheritedRule::ScalaUnknownCoverage => {
                    WalkClosure::Open
                }
            };
        }
        match rule {
            InheritedRule::Java if self.candidates.len() == 1 => WalkClosure::Unique,
            InheritedRule::Java => WalkClosure::Ambiguous,
            _ => WalkClosure::Open,
        }
    }

    pub fn is_open(&self) -> bool {
        !self.frontiers.is_empty() || !self.reasons.is_empty()
    }
    fn stopped(reason: &'static str) -> Self {
        Self {
            reasons: BTreeSet::from([reason]),
            ..Self::default()
        }
    }
    fn absorb(&mut self, other: &Self) {
        self.candidates.extend(other.candidates.clone());
        self.frontiers.extend(other.frontiers.iter().cloned());
        self.reasons.extend(other.reasons.iter().copied());
    }
}

/// Keep the candidates an owner in `package` inherits: its own declarations,
/// public and protected members, and package-private members of its own
/// package (JLS 8.5). An unknown access or package leaves the answer Open.
fn retain_inherited(
    answer: &mut WalkAnswer,
    declared: &BTreeSet<BridgedDeclaration>,
    package: Option<&str>,
) {
    let reasons = &mut answer.reasons;
    answer.candidates.retain(|_, member| match member.access {
        _ if declared.contains(&member.declaration) => true,
        MemberAccess::Public | MemberAccess::Protected => true,
        MemberAccess::PackagePrivate => match (package, member.declaring_package.as_deref()) {
            (Some(package), Some(declaring)) => declaring == package,
            _ => {
                reasons.insert("inherited_access_open");
                false
            }
        },
        MemberAccess::Private => false,
        MemberAccess::Unknown => {
            reasons.insert("inherited_access_open");
            false
        }
    });
}

struct Frame {
    owner: BridgedDeclaration,
    inventory: OwnerInventory,
    parents: Vec<BridgedDeclaration>,
    next: usize,
    answer: WalkAnswer,
}

/// One walk reads parents and inventories through one source. A stopped memo
/// is valid only for the walk that recorded it.
pub(super) struct InheritedMemberWalk<S> {
    source: S,
    memo: HashMap<BridgedDeclaration, WalkAnswer>,
    remaining_expansions: Rc<Cell<usize>>,
}

impl<S: InheritedParentSource + InheritedInventorySource> InheritedMemberWalk<S> {
    pub fn new(source: S) -> Self {
        Self::with_shared_allowance(source, Rc::new(Cell::new(OWNER_EXPANSION_LIMIT)))
    }

    /// Share the owner allowance across sibling and nested level walks.
    pub fn with_shared_allowance(source: S, remaining: Rc<Cell<usize>>) -> Self {
        Self {
            source,
            memo: HashMap::new(),
            remaining_expansions: remaining,
        }
    }

    pub fn inherited(
        &mut self,
        owner: &BridgedDeclaration,
        session: &ResolutionSession,
    ) -> Result<WalkAnswer> {
        let parents = self.source.direct_parents(owner, session)?;
        let mut result = WalkAnswer {
            frontiers: parents.frontiers,
            ..WalkAnswer::default()
        };
        if !parents.complete {
            result.reasons.insert("inherited_parent_open");
        }
        if !session.observe_cancellation() {
            result.reasons.insert("inherited_session_stopped");
            return Ok(result);
        }
        let mut definite = parents.definite;
        definite.sort();
        definite.dedup();
        for parent in definite {
            result.absorb(&self.walk(parent, session)?);
        }
        // The last edge, from the direct parents into `owner`, follows the same
        // access rule as every edge inside the walk.
        if !result.candidates.is_empty() {
            let package = self.source.owner_package(owner, session)?;
            retain_inherited(&mut result, &BTreeSet::new(), package.as_deref());
        }
        Ok(result)
    }

    fn walk(
        &mut self,
        root: BridgedDeclaration,
        session: &ResolutionSession,
    ) -> Result<WalkAnswer> {
        let mut stack: Vec<Frame> = Vec::new();
        let mut pending = Some(root.clone());
        loop {
            if let Some(owner) = pending.take() {
                if !session.scope_step() {
                    return Ok(WalkAnswer::stopped("inherited_session_stopped"));
                }
                if let Some(done) = self.memo.get(&owner) {
                    if let Some(frame) = stack.last_mut() {
                        frame.answer.absorb(done);
                        continue;
                    }
                    return Ok(done.clone());
                }
                if let Some(position) = stack.iter().position(|f| f.owner == owner) {
                    for frame in &mut stack[position..] {
                        frame.answer.reasons.insert("inherited_cycle");
                    }
                    continue;
                }
                let remaining = self.remaining_expansions.get();
                if remaining == 0 {
                    let stopped = WalkAnswer::stopped("inherited_walk_budget_exhausted");
                    self.memo.insert(owner, stopped.clone());
                    if let Some(frame) = stack.last_mut() {
                        frame.answer.absorb(&stopped);
                        continue;
                    }
                    return Ok(stopped);
                }
                self.remaining_expansions.set(remaining - 1);
                let inventory = self.source.owner_inventory(&owner, session)?;
                let parents = self.source.direct_parents(&owner, session)?;
                let mut answer = WalkAnswer {
                    frontiers: inventory.frontiers.clone(),
                    ..WalkAnswer::default()
                };
                answer.frontiers.extend(parents.frontiers);
                if !inventory.complete {
                    answer.reasons.insert("inherited_inventory_open");
                }
                if !parents.complete {
                    answer.reasons.insert("inherited_parent_open");
                }
                if !session.observe_cancellation() {
                    answer.reasons.insert("inherited_session_stopped");
                }
                for member in &inventory.declared {
                    if !session.scope_step() {
                        answer.reasons.insert("inherited_session_stopped");
                        break;
                    }
                    answer
                        .candidates
                        .insert(member.declaration.clone(), member.clone());
                }
                let mut definite = parents.definite;
                definite.sort();
                definite.dedup();
                stack.push(Frame {
                    owner,
                    inventory,
                    parents: definite,
                    next: 0,
                    answer,
                });
                continue;
            }
            let Some(top) = stack.last_mut() else {
                return Ok(self.memo[&root].clone());
            };
            if top.next < top.parents.len() {
                if !session.scope_step() {
                    top.answer.reasons.insert("inherited_session_stopped");
                    top.next = top.parents.len();
                    continue;
                }
                let parent = top.parents[top.next].clone();
                top.next += 1;
                pending = Some(parent);
                continue;
            }
            let frame = stack.pop().expect("nonempty walk stack");
            let mut answer = frame.answer;
            let declared_names: BTreeSet<_> = frame
                .inventory
                .declared
                .iter()
                .map(|m| m.name.clone())
                .collect();
            let declared_ids: BTreeSet<_> = frame
                .inventory
                .declared
                .iter()
                .map(|m| m.declaration.clone())
                .collect();
            answer.candidates.retain(|_, member| {
                declared_ids.contains(&member.declaration) || !declared_names.contains(&member.name)
            });
            retain_inherited(
                &mut answer,
                &declared_ids,
                frame.inventory.package.as_deref(),
            );
            self.memo.insert(frame.owner, answer.clone());
            if let Some(parent) = stack.last_mut() {
                parent.answer.absorb(&answer);
            } else {
                return Ok(answer);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct Fake {
        parents: HashMap<BridgedDeclaration, Vec<BridgedDeclaration>>,
        members: HashMap<BridgedDeclaration, Vec<MemberTypeCandidate>>,
        packages: HashMap<BridgedDeclaration, Arc<str>>,
    }
    impl InheritedParentSource for Fake {
        fn direct_parents(
            &mut self,
            owner: &BridgedDeclaration,
            session: &ResolutionSession,
        ) -> Result<ParentInventory> {
            assert!(session.scope_step());
            Ok(ParentInventory {
                definite: self.parents.get(owner).cloned().unwrap_or_default(),
                complete: true,
                ..ParentInventory::default()
            })
        }
    }
    impl InheritedInventorySource for Fake {
        fn owner_inventory(
            &mut self,
            owner: &BridgedDeclaration,
            session: &ResolutionSession,
        ) -> Result<OwnerInventory> {
            assert!(session.scope_step());
            Ok(OwnerInventory {
                declared: self.members.get(owner).cloned().unwrap_or_default(),
                package: Some(
                    self.packages
                        .get(owner)
                        .cloned()
                        .unwrap_or_else(|| Arc::from("p")),
                ),
                complete: true,
                frontiers: BTreeSet::new(),
            })
        }

        fn owner_package(
            &mut self,
            owner: &BridgedDeclaration,
            _session: &ResolutionSession,
        ) -> Result<Option<Arc<str>>> {
            Ok(Some(
                self.packages
                    .get(owner)
                    .cloned()
                    .unwrap_or_else(|| Arc::from("p")),
            ))
        }
    }
    fn id(n: u32) -> BridgedDeclaration {
        BridgedDeclaration::Source {
            mount_ordinal: SelectedResolutionMountOrdinal::new(0),
            local_key: ResolutionLocalKey::new(n.into()),
        }
    }
    fn fake(edges: &[(u32, u32)]) -> Fake {
        let mut parents: HashMap<_, Vec<_>> = HashMap::new();
        for &(from, to) in edges {
            parents.entry(id(from)).or_default().push(id(to));
        }
        Fake {
            parents,
            members: HashMap::new(),
            packages: HashMap::new(),
        }
    }
    fn member(n: u32, access: MemberAccess, package: &str) -> MemberTypeCandidate {
        MemberTypeCandidate {
            declaration: id(n),
            name: Arc::from("T"),
            access,
            declaring_package: Some(Arc::from(package)),
        }
    }
    #[test]
    fn reopened_parent_source_keeps_external_and_stale_authority_open() {
        use crate::analyzer::project::{OverlayProject, Project, TestProject};
        use crate::analyzer::store::resolution_operation::{
            SelectedResolutionOperationInput, SelectedResolutionOperationOpenOutcome,
        };
        use crate::analyzer::store::resolution_selection::SelectedResolutionLanguage;
        use brokk_bifrost_core::analyzer::model::Language;

        let (store, workspace, snapshots) =
            crate::analyzer::store::resolution_selection::tests::qualifier_completion_gap_fixture_in_language(
                crate::analyzer::store::AnalyzerStore::open_ephemeral().unwrap(),
                Language::Java,
            );
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("fixture.java");
        std::fs::write(&file, "class Child extends Parent {}\nclass Parent {}\n").unwrap();
        let project = OverlayProject::new(Arc::new(TestProject::new(root.path(), Language::Java)));
        let cancellation = crate::CancellationToken::new();
        let languages = [SelectedResolutionLanguage::new("java", Language::Java)];
        let SelectedResolutionOperationOpenOutcome::Ready(operation) = store
            .open_selected_resolution_operation(
                SelectedResolutionOperationInput::new(
                    &project,
                    &workspace,
                    &snapshots,
                    &languages,
                    &[],
                ),
                &cancellation,
            )
            .unwrap()
        else {
            panic!("fixture opens");
        };
        let mut source = ReopenedInheritedParentSource::open(
            operation.worker_store(),
            operation.worker_input().clone(),
            &cancellation,
            None,
        )
        .unwrap();
        let session = ResolutionSession::unbounded();
        let external = BridgedDeclaration::External(ExternalOwnerIdentity {
            provider_id: Arc::from("test"),
            owner_fqn: Arc::from("example.Parent"),
        });
        {
            let mut inventory = ReopenedInheritedInventorySource::new(&mut source, "T");
            let unknown = inventory.owner_inventory(&id(1), &session).unwrap();
            assert!(!unknown.complete);
            assert!(
                unknown
                    .frontiers
                    .contains("inherited_member_type_coverage_unknown")
            );
            let external_inventory = inventory.owner_inventory(&external, &session).unwrap();
            assert!(!external_inventory.complete);
            assert!(
                external_inventory
                    .frontiers
                    .contains("inherited_external_inventory")
            );
        }
        let answer = source.direct_parents(&external, &session).unwrap();
        assert!(!answer.complete);
        assert!(answer.frontiers.contains("inherited_external_parent"));
        assert!(project.set(file, "class Child extends Changed {}".to_string()));
        let answer = source.direct_parents(&id(1), &session).unwrap();
        assert!(!answer.complete);
        assert!(answer.frontiers.contains("inherited_selection_stale"));
        assert_ne!(
            project.analysis_generation(),
            operation.worker_input().analysis_generation
        );
        let mut reopened = ReopenedInheritedParentSource::open(
            operation.worker_store(),
            operation.worker_input().clone(),
            &cancellation,
            None,
        )
        .unwrap();
        let answer = reopened.direct_parents(&id(1), &session).unwrap();
        assert!(!answer.complete);
        assert!(answer.frontiers.contains("inherited_selection_stale"));
    }

    #[test]
    fn reopened_inventory_requires_member_type_coverage_for_absence() {
        use crate::analyzer::project::{OverlayProject, TestProject};
        use crate::analyzer::store::resolution_operation::{
            SelectedResolutionOperationInput, SelectedResolutionOperationOpenOutcome,
        };
        use crate::analyzer::store::resolution_selection::SelectedResolutionLanguage;
        use brokk_bifrost_core::analyzer::model::Language;
        use rusqlite::params;

        for (claim, listed) in [
            (Some("complete"), true),
            (Some("complete"), false),
            (Some("open"), false),
            (None, false),
        ] {
            let (store, workspace, snapshots) =
                crate::analyzer::store::resolution_selection::tests::qualifier_completion_gap_fixture_in_language(
                    crate::analyzer::store::AnalyzerStore::open_ephemeral().unwrap(),
                    Language::Java,
                );
            store.conn.execute_fixture(move |conn| {
                let tx = conn.transaction().unwrap();
                let blob_id: i64 = tx.query_row("SELECT id FROM blobs WHERE lang='java'", [], |row| row.get(0)).unwrap();
                tx.execute("INSERT INTO resolution_semantic_catalog(blob_id,local_key,identity_digest) VALUES(?1,1,CAST(printf('%032d',1) AS BLOB))", params![blob_id]).unwrap();
                tx.execute("INSERT INTO resolution_semantic_catalog(blob_id,local_key,identity_digest) VALUES(?1,2,CAST(printf('%032d',2) AS BLOB))", params![blob_id]).unwrap();
                tx.execute("INSERT INTO resolution_member_scope_properties(blob_id,definition_semantic_key,scope_head_node_key,scope_kind) VALUES(?1,1,1,'type_body')", params![blob_id]).unwrap();
                if let Some(claim) = claim {
                    tx.execute("INSERT INTO resolution_member_type_coverage(blob_id,definition_semantic_key,scope_head_node_key,coverage,open_reason) VALUES(?1,1,1,?2,?3)", params![blob_id, claim, if claim == "open" { Some("malformed") } else { None }]).unwrap();
                }
                if listed {
                    tx.execute("INSERT INTO resolution_member_owner_properties(blob_id,definition_semantic_key,owner_definition_semantic_key,owner_scope_head_node_key,member_kind,member_access,qualifier_compatibility,member_name) VALUES(?1,2,1,1,'nested_type','type','type_only','T')", params![blob_id]).unwrap();
                }
                tx.commit().unwrap();
            });
            let root = tempfile::tempdir().unwrap();
            let project =
                OverlayProject::new(Arc::new(TestProject::new(root.path(), Language::Java)));
            let cancellation = crate::CancellationToken::new();
            let languages = [SelectedResolutionLanguage::new("java", Language::Java)];
            let SelectedResolutionOperationOpenOutcome::Ready(operation) = store
                .open_selected_resolution_operation(
                    SelectedResolutionOperationInput::new(
                        &project,
                        &workspace,
                        &snapshots,
                        &languages,
                        &[],
                    ),
                    &cancellation,
                )
                .unwrap()
            else {
                panic!("fixture opens")
            };
            let mut source = ReopenedInheritedParentSource::open(
                operation.worker_store(),
                operation.worker_input().clone(),
                &cancellation,
                None,
            )
            .unwrap();
            let inventory = ReopenedInheritedInventorySource::new(&mut source, "T")
                .owner_inventory(&id(1), &ResolutionSession::unbounded())
                .unwrap();
            assert_eq!(
                inventory.declared.len(),
                usize::from(listed),
                "{inventory:?}"
            );
            assert_eq!(inventory.complete, claim == Some("complete"));
            if claim == Some("open") {
                assert!(inventory.frontiers.contains("malformed"));
            }
            if claim.is_none() {
                assert!(
                    inventory
                        .frontiers
                        .contains("inherited_member_type_coverage_unknown")
                );
            }
        }
    }

    #[test]
    fn cycles_taint_every_start() {
        let edges = [(1, 2), (2, 1), (1, 3), (3, 2)];
        for start in 1..=3 {
            let mut walk = InheritedMemberWalk::new(fake(&edges));
            let result = walk
                .walk(id(start), &ResolutionSession::unbounded())
                .unwrap();
            assert!(result.reasons.contains("inherited_cycle"));
            assert!(result.candidates.is_empty());
        }
    }
    #[test]
    fn diamond_deduplicates_and_package_private_does_not_reappear() {
        let mut source = fake(&[(1, 2), (1, 3), (2, 4), (3, 4)]);
        source
            .members
            .insert(id(4), vec![member(9, MemberAccess::Public, "p")]);
        let mut walk = InheritedMemberWalk::new(source);
        let result = walk.walk(id(1), &ResolutionSession::unbounded()).unwrap();
        assert_eq!(result.candidates.len(), 1);
        assert!(!result.is_open());
        let mut source = fake(&[(1, 2), (2, 3)]);
        source
            .members
            .insert(id(3), vec![member(9, MemberAccess::PackagePrivate, "p")]);
        source.packages.insert(id(2), Arc::from("q"));
        let mut walk = InheritedMemberWalk::new(source);
        let result = walk.walk(id(1), &ResolutionSession::unbounded()).unwrap();
        assert!(result.candidates.is_empty());
        assert!(!result.is_open());
    }
    #[test]
    fn budget_stop_is_open_and_operation_local() {
        let edges: Vec<_> = (1..70).map(|n| (n, n + 1)).collect();
        let mut walk = InheritedMemberWalk::new(fake(&edges));
        let result = walk.walk(id(1), &ResolutionSession::unbounded()).unwrap();
        assert!(result.reasons.contains("inherited_walk_budget_exhausted"));
        let mut fresh = InheritedMemberWalk::new(fake(&edges));
        let result = fresh.walk(id(68), &ResolutionSession::unbounded()).unwrap();
        assert!(!result.is_open());
        assert_eq!(
            result.closure(InheritedRule::KotlinOther),
            WalkClosure::Open
        );
        assert_eq!(
            result.closure(InheritedRule::KotlinSuperclassNested),
            WalkClosure::Absent
        );
    }
    #[test]
    fn sibling_walks_share_owner_allowance() {
        let edges: Vec<_> = (1..64).map(|n| (n, n + 1)).collect();
        let mut walk = InheritedMemberWalk::new(fake(&edges));
        let session = ResolutionSession::unbounded();
        assert!(!walk.walk(id(1), &session).unwrap().is_open());
        assert!(
            walk.walk(id(100), &session)
                .unwrap()
                .reasons
                .contains("inherited_walk_budget_exhausted")
        );
    }

    #[test]
    fn separate_level_walks_share_owner_allowance() {
        let remaining = Rc::new(Cell::new(1));
        let session = ResolutionSession::unbounded();
        let source = fake(&[]);
        let mut first =
            InheritedMemberWalk::with_shared_allowance(source.clone(), Rc::clone(&remaining));
        let mut second = InheritedMemberWalk::with_shared_allowance(source, remaining);
        assert!(!first.walk(id(1), &session).unwrap().is_open());
        assert!(second.walk(id(2), &session).unwrap().is_open());
    }
}
