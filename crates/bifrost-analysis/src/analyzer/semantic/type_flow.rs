//! Class-set type propagation adapter contract.
//!
//! The class-set engine in `brokk-bifrost-flow` propagates one class atom per
//! class-producing site through the existing value-flow solver and asks, at
//! every member access, which classes the receiver may hold. Everything the
//! engine cannot derive from the language-neutral semantic IR is answered by a
//! per-language [`TypeFlowAdapter`]: which call constructs a class, which
//! class a constant or container literal has, which class a parameter
//! declares, which member a call or load accesses, and whether a class
//! declares a member. JavaScript, Ruby, and PHP adapters are follow-on work;
//! they supply seeds and member lookup only, never a solver.

use crate::analyzer::languages::language_support_for_hook;
use crate::analyzer::semantic::oracle::CandidateCoverage;
use crate::analyzer::semantic::{
    AdapterSemanticsVersion, AllocationSite, ContentIdentity, GuardFact, MemoryLocation,
    OverlaySnapshotId, ProcedureHandle, ProgramPointId, SemanticCallSite, SemanticLocator,
    SemanticValue, SourceRevision, SourceSpan, StableDigest, ValueId, WorkspaceMountId,
    WorkspaceRelativePath,
};
use crate::analyzer::semantic_model::{
    SemanticModelCompleteness, SemanticModelMemberTargetDisposition, SemanticModelOverlay,
    SemanticModelSymbol, SemanticModelSymbolKind,
};
use crate::analyzer::usages::get_type::TypeLookupType;
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, WorkspaceAnalyzer};
use brokk_bifrost_core::analyzer::prepared_syntax::{
    PreparedSourceOrigin, PreparedSyntaxSource, PreparedSyntaxTree,
};
pub use brokk_bifrost_semantic::analyzer::semantic::type_flow::*;
use std::path::Path;
use std::sync::Arc;
#[doc(hidden)]
pub fn enclosing_workspace_class_unit(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    span: SourceSpan,
    mut accepts: impl FnMut(&CodeUnit) -> bool,
) -> Option<CodeUnit> {
    let range = analyzer_range_for_span(span);
    let mut unit = analyzer.enclosing_code_unit(file, &range)?;
    loop {
        if unit.is_class() && accepts(&unit) {
            return Some(unit);
        }
        unit = analyzer.parent_of(&unit)?;
    }
}

/// Resolve one external class from the active model after filtering by the
/// requested language and owner-less class shape. Eligible records with the
/// same exact qualified name describe one class; complete surfaces and then
/// the smallest ID choose its stable representative.
#[doc(hidden)]
pub fn external_class_identity(
    overlay: Option<&SemanticModelOverlay>,
    language: Language,
    qualified_name: &str,
    semantic_model_id: Option<&str>,
    cache: &mut ExternalClassCache,
) -> Option<ClassIdentity> {
    external_class_identity_with_visits(
        overlay,
        language,
        qualified_name,
        semantic_model_id,
        cache,
        &mut || Ok::<_, std::convert::Infallible>(()),
    )
    .unwrap_or_else(|never| match never {})
}

/// The same canonical selection with streaming candidates and caller-owned
/// accounting. A failed visit never inserts a partial result into the cache.
#[doc(hidden)]
pub fn external_class_identity_with_visits<E>(
    overlay: Option<&SemanticModelOverlay>,
    language: Language,
    qualified_name: &str,
    semantic_model_id: Option<&str>,
    cache: &mut ExternalClassCache,
    visit: &mut impl FnMut() -> Result<(), E>,
) -> Result<Option<ClassIdentity>, E> {
    visit()?;
    let key = (
        language,
        qualified_name.into(),
        semantic_model_id.map(Box::from),
    );
    if let Some(cached) = cache.get(&key) {
        return Ok(cached.clone());
    }
    let resolved = (|| -> Result<Option<ClassIdentity>, E> {
        let Some(overlay) = overlay else {
            return Ok(None);
        };
        let eligible = |symbol: &SemanticModelSymbol| {
            symbol.language == language.config_label()
                && symbol.owner_id.is_none()
                && symbol.kind == SemanticModelSymbolKind::Class
                && !symbol.provenance.ambiguous
        };
        let mut fallback = None;
        let mut conflicting_names = false;
        let mut exact = false;
        // Both branches feed the same selection, without allocating a match
        // vector before the caller has charged the candidates.
        let mut candidate = |symbol: std::sync::Arc<SemanticModelSymbol>| -> Result<(), E> {
            visit()?;
            if eligible(&symbol) {
                if symbol.qualified_name == qualified_name {
                    exact = true;
                }
                if fallback
                    .as_ref()
                    .is_some_and(|name| name != &symbol.qualified_name)
                {
                    conflicting_names = true;
                }
                fallback = Some(symbol.qualified_name.clone());
            }
            Ok(())
        };
        match semantic_model_id {
            Some(id) => {
                for symbol in overlay.symbol_candidates_with_id(id) {
                    candidate(symbol)?;
                }
            }
            None => {
                for symbol in overlay.symbol_candidates_named(qualified_name) {
                    candidate(symbol)?;
                }
            }
        }
        let group_name = if semantic_model_id.is_none() && exact {
            qualified_name
        } else if conflicting_names {
            return Ok(None);
        } else if let Some(name) = fallback.as_deref() {
            name
        } else {
            return Ok(None);
        };
        let mut representative = None;
        let mut requested_id_present = semantic_model_id.is_none();
        for symbol in overlay.symbol_candidates_named(group_name) {
            visit()?;
            if symbol.qualified_name != group_name || !eligible(&symbol) {
                continue;
            }
            requested_id_present |= semantic_model_id == Some(symbol.id.as_str());
            representative = match representative {
                None => Some(symbol),
                Some(previous) => overlay.class_representative([previous, symbol]),
            };
        }
        if !requested_id_present {
            return Ok(None);
        }
        Ok(representative.map(|symbol| ClassIdentity::External {
            qualified_name: symbol.qualified_name.clone().into_boxed_str(),
            symbol_id: symbol.id.clone().into_boxed_str(),
        }))
    })()?;
    cache.insert(key, resolved.clone());
    Ok(resolved)
}

#[doc(hidden)]
pub fn class_seed_from_lookup_types(
    overlay: Option<&SemanticModelOverlay>,
    language: Language,
    types: &[TypeLookupType],
) -> ClassSeed {
    let [lookup] = types else {
        return if types.is_empty() {
            ClassSeed::NotApplicable
        } else {
            ClassSeed::Unknown(UnknownReason::AmbiguousCallee)
        };
    };
    if let Some(symbol_id) = lookup.semantic_model_id.as_deref() {
        return match lookup.definitions.as_slice() {
            [_] => external_class_identity(
                overlay,
                language,
                &lookup.fqn,
                Some(symbol_id),
                &mut ExternalClassCache::default(),
            )
            .map(ClassSeed::Class)
            .unwrap_or(ClassSeed::Unknown(UnknownReason::ExternalNotModeled)),
            _ => ClassSeed::Unknown(UnknownReason::AmbiguousCallee),
        };
    }
    match lookup.definitions.as_slice() {
        [definition] if definition.is_class() => {
            ClassSeed::Class(ClassIdentity::Workspace(definition.clone()))
        }
        [_] => ClassSeed::NotApplicable,
        [] => ClassSeed::NotApplicable,
        _ => ClassSeed::Unknown(UnknownReason::AmbiguousCallee),
    }
}

#[doc(hidden)]
pub fn external_member_lookup(
    overlay: &SemanticModelOverlay,
    owner_id: &str,
    member: &str,
) -> MemberLookup {
    let matched = overlay.symbols_with_id(owner_id);
    let [owner] = matched.records.as_slice() else {
        return MemberLookup::Unknown(UnknownReason::PackIncomplete);
    };
    if owner.owner_id.is_some() || owner.kind != SemanticModelSymbolKind::Class {
        return MemberLookup::Unknown(UnknownReason::PackIncomplete);
    }
    let owners = overlay
        .symbols_named(&owner.qualified_name)
        .records
        .into_iter()
        .filter(|candidate| {
            candidate.qualified_name == owner.qualified_name
                && candidate.language == owner.language
                && candidate.owner_id.is_none()
                && candidate.kind == SemanticModelSymbolKind::Class
                && !candidate.provenance.ambiguous
        })
        .collect::<Vec<_>>();
    let mut declarations = Vec::new();
    let mut has_member_record = false;
    let mut complete_surface = false;
    let mut coverage_open = false;
    for candidate in owners {
        complete_surface |=
            candidate.provenance.completeness == SemanticModelCompleteness::Complete;
        let raw_members = overlay
            .members_of(&candidate.id)
            .records
            .into_iter()
            .filter(|record| {
                record.owner_id.as_deref() == Some(candidate.id.as_str())
                    && record.language == candidate.language
                    && record.name == member
            })
            .collect::<Vec<_>>();
        has_member_record |= !raw_members.is_empty();
        let matched = overlay.member_target_on_owner(&candidate.id, member);
        match matched.disposition {
            SemanticModelMemberTargetDisposition::Unique => declarations.extend(matched.records),
            SemanticModelMemberTargetDisposition::Conflict
                if overlay.member_present_on_owner(&candidate.id, member) =>
            {
                declarations.extend(matched.records);
                coverage_open = true;
            }
            SemanticModelMemberTargetDisposition::Absent => {}
            SemanticModelMemberTargetDisposition::Incomplete
            | SemanticModelMemberTargetDisposition::Conflict => coverage_open = true,
        }
    }
    declarations.sort_by(|left, right| left.id.cmp(&right.id));
    declarations.dedup_by(|left, right| left.id == right.id);
    if !declarations.is_empty() {
        return MemberLookup::Present(MemberLookupHit::new(
            MemberDeclaration::External(ExternalMemberDeclaration::new(
                declarations
                    .into_iter()
                    .map(|record| Box::from(record.id.as_str())),
            )),
            if coverage_open {
                CandidateCoverage::Open
            } else {
                CandidateCoverage::Exhaustive
            },
        ));
    }
    // An inherited member on an incomplete ancestry path must not become a
    // proven absence (#5121). Restore the rule #4942 dropped for multi-owner lookups.
    if coverage_open || has_member_record {
        return MemberLookup::Unknown(UnknownReason::PackIncomplete);
    }
    if !complete_surface
        || overlay
            .gapped_member_surface(&owner.qualified_name, member)
            .is_some()
    {
        return MemberLookup::Unknown(UnknownReason::PackIncomplete);
    }
    MemberLookup::Absent
}

pub fn file_for_locator(
    workspace: &WorkspaceAnalyzer,
    locator: &SemanticLocator,
) -> Option<ProjectFile> {
    workspace
        .analyzer()
        .project()
        .file_by_rel_path(Path::new(locator.path().as_str()))
}

/// Accept prepared syntax only when it is the exact indexed snapshot from
/// which `procedure` was materialized. A mismatch is typed as uncertain flow:
/// adapters must fail closed instead of reading AST fields at stale offsets.
pub fn validate_prepared_syntax_for_procedure(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    file: &ProjectFile,
    prepared: Arc<PreparedSyntaxTree>,
) -> Result<Arc<PreparedSyntaxTree>, UnknownReason> {
    if !matches!(prepared.backing(), PreparedSyntaxSource::Indexed(_)) {
        return Err(UnknownReason::UncertainFlow);
    }
    validate_prepared_syntax_source_for_procedure(workspace, procedure, file, prepared)
}

#[doc(hidden)]
pub fn prepared_syntax_for_procedure(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    file: &ProjectFile,
    prepared: Option<Arc<PreparedSyntaxTree>>,
) -> Result<Arc<PreparedSyntaxTree>, UnknownReason> {
    let prepared = prepared.ok_or(UnknownReason::UncertainFlow)?;
    validate_prepared_syntax_for_procedure(workspace, procedure, file, prepared)
}

/// Validate source identity without requiring indexed declaration access.
/// Bounded structural queries retain exact-source trees; their bytes, dialect,
/// mount, revision and current indexed snapshot must still match the artifact.
pub fn validate_prepared_syntax_source_for_procedure(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    file: &ProjectFile,
    prepared: Arc<PreparedSyntaxTree>,
) -> Result<Arc<PreparedSyntaxTree>, UnknownReason> {
    let key = procedure.artifact().key();
    let path_matches =
        WorkspaceRelativePath::try_from_path(file.rel_path()).is_ok_and(|path| &path == key.path());
    let content = ContentIdentity::from_digest(StableDigest::from_array(prepared.source_sha256()));
    let revision_matches = match (key.revision(), prepared.origin()) {
        (SourceRevision::Disk { content: expected }, PreparedSourceOrigin::Disk) => {
            content == expected
        }
        (
            SourceRevision::Overlay {
                content: expected,
                snapshot,
            },
            PreparedSourceOrigin::Overlay,
        ) => {
            content == expected
                && prepared.overlay_revision().is_some_and(|revision| {
                    OverlaySnapshotId::hash_bytes(revision.get().to_le_bytes()) == snapshot
                })
        }
        _ => false,
    };
    let exact = path_matches
        && key.mount() == WorkspaceMountId::from_root(file.root())
        && key.language() == prepared.dialect()
        && revision_matches
        && workspace
            .analyzer()
            .indexed_source_matches(file, prepared.source());
    if !exact {
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "policy.units unbounded origin={}:{} cause=snapshot",
                file!(),
                line!()
            )
        });
        workspace.analyzer().mark_execution_dependent();
    }
    exact
        .then_some(prepared)
        .ok_or(UnknownReason::UncertainFlow)
}

/// Per-language facts the class-set engine cannot derive from the IR.
/// Implementations are zero-sized and `'static`; every method receives the
/// workspace it should consult. `class_hierarchy` describes the known
/// workspace: an empty complete descendant list authorizes the engine's
/// closed-workspace leaf-receiver rule, and does not claim that external
/// subclasses cannot exist.
pub trait TypeFlowAdapter: Send + Sync {
    fn language(&self) -> Language;

    /// Stable identity of every answer this adapter can provide. Implementors
    /// must rotate it whenever any type-flow method changes behavior for
    /// unchanged semantic inputs.
    fn semantics_version(&self) -> AdapterSemanticsVersion;

    fn constructed_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        call: &SemanticCallSite,
    ) -> ClassSeed;
    /// Complete runtime class set of a callable result with an explicit
    /// exact-return claim. These class facts are independent of value-flow
    /// transfers from call inputs.
    fn exact_call_result_class(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _call: &SemanticCallSite,
    ) -> Option<Box<[ClassIdentity]>> {
        None
    }
    /// Whether this exact call or access result reaches the receiver through
    /// the language's stable-local proof. A true result lets type flow ignore
    /// value transfers from the producer's inputs when computing its class set.
    fn exact_result_receiver_is_stable(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _receiver: ValueId,
        _call: &SemanticCallSite,
        _origin: &ConstructorResultOrigin,
    ) -> bool {
        false
    }
    /// Class of a value produced by an exact attribute or subscript access.
    /// Implementations must return a class only when the access declaration
    /// explicitly claims an exact runtime return class.
    fn memory_load_result_class(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _location: &MemoryLocation,
        _result: ValueId,
    ) -> ClassSeed {
        ClassSeed::NotApplicable
    }
    fn constant_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        value: &SemanticValue,
    ) -> ClassSeed;
    /// Class of a computation whose operand dependencies do not establish
    /// class identity. An adapter may classify the result from structured
    /// language semantics; an unmodeled computation remains explicitly open.
    fn computed_class(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _value: &SemanticValue,
    ) -> ClassSeed {
        ClassSeed::Unknown(UnknownReason::UncertainFlow)
    }
    /// Classifies a retained value whose semantic kind has no built-in
    /// class-set seed. This is the adapter's fail-closed seam for structured
    /// language values such as callable expressions and literals that are
    /// neither constants nor allocation sites in semantic IR. The planner
    /// invokes this only for data origins; call-site callee values are excluded
    /// because callable targets are control-flow identities, not runtime data
    /// flowing through the call's arguments or result.
    fn retained_value_class(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _value: &SemanticValue,
    ) -> ClassSeed {
        ClassSeed::NotApplicable
    }
    fn allocation_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        allocation: &AllocationSite,
    ) -> ClassSeed;
    fn declared_parameter_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        ordinal: u32,
    ) -> ClassSeed;
    /// Whether this exact declared-parameter origin is safe to admit to the
    /// Conditional absent-member tier for `class`. Adapters must prove a
    /// single closed workspace class from the parameter's annotation; other
    /// languages and unproved origins stay excluded.
    fn declared_parameter_conditional_origin_is_closed(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _class: &ClassIdentity,
        _origin: &SourceSite,
    ) -> bool {
        false
    }
    /// Program points and results of plain local memory loads whose modeled stores exhaust the
    /// possible values. A certificate requires closed initialization, aliases
    /// and mutation effects; plain indexing alone is not sufficient. Missing
    /// or stopped proofs leave the load's unknown remainder in place.
    fn closed_memory_loads(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<Vec<(ProgramPointId, ValueId)>, crate::analyzer::semantic::SemanticBudgetExceeded>
    {
        Ok(Vec::new())
    }

    /// Whether this memory-location shape can be closed after class refinement.
    ///
    /// This is a cheap structural filter. The plan calls the class-aware method
    /// only for locations accepted here.
    fn memory_load_supports_class_closure(&self, _location: &MemoryLocation) -> bool {
        false
    }

    /// Whether an indexed load's retained memory location has the runtime
    /// meaning modeled by the IR for every exact base class in `classes`.
    ///
    /// The caller supplies an exhaustive, uncertainty-free class set. An
    /// adapter must keep subclasses and classes with overloadable access
    /// protocols open. A positive answer removes only the synthetic unknown
    /// load result; modeled stores and their ordinary value flow remain.
    fn memory_load_is_closed_for_classes(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _location: &MemoryLocation,
        _classes: &[ClassIdentity],
    ) -> bool {
        false
    }

    fn accessed_member(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        site: MemberAccessQuery<'_>,
    ) -> Option<Box<str>>;
    fn member_lookup(
        &self,
        workspace: &WorkspaceAnalyzer,
        kind: MemberAccessKind,
        class: &ClassIdentity,
        member: &str,
    ) -> MemberLookup;

    /// Look up a member called through one receiver value, retaining the
    /// receiver and its reaching constructor evidence for languages that can
    /// prove an exact instance. The default preserves the class-only lookup
    /// contract for adapters without receiver-specific dispatch rules.
    fn member_lookup_for_receiver(
        &self,
        workspace: &WorkspaceAnalyzer,
        query: MemberReceiverQuery<'_>,
    ) -> MemberLookup {
        let _ = (
            query.procedure,
            query.receiver,
            query.call,
            query.constructor,
        );
        self.member_lookup(workspace, MemberAccessKind::Call, query.class, query.member)
    }

    fn enclosing_class(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
    ) -> Option<ClassIdentity> {
        None
    }

    /// Whether the receiver binding retains its entry identity throughout the
    /// procedure, including syntax whose effects are not represented in IR.
    /// This proves binding stability, not membership in the enclosing class:
    /// callers can still supply a different object through an unbound call.
    fn receiver_binding_is_stable(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
    ) -> bool {
        false
    }

    /// Whether the exact class's member names cannot be extended by runtime
    /// writes. This does not imply that subclasses or stored contents are closed.
    fn member_surface_is_closed(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _class: &ClassIdentity,
    ) -> bool {
        false
    }

    fn class_hierarchy(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _class: &ClassIdentity,
    ) -> ClassHierarchy {
        ClassHierarchy::unknown()
    }

    /// Whether truth testing an instance can execute user-defined effects.
    /// A true answer permits a field guard to constrain a subsequent reread.
    fn truthiness_is_pure(&self, _workspace: &WorkspaceAnalyzer, _class: &ClassIdentity) -> bool {
        false
    }

    /// Whether loading this member can execute user-defined effects.
    fn member_access_is_pure(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _class: &ClassIdentity,
        _member: &str,
    ) -> bool {
        false
    }

    /// What the class declaration itself binds under this member name,
    /// beyond the instance stores the field-store survey collected.
    fn class_body_member_binding(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _class: &ClassIdentity,
        _member: &str,
    ) -> ClassBodyMemberBinding {
        ClassBodyMemberBinding::Unclassified
    }

    /// Whether repeated accesses to this instance field use ordinary storage,
    /// rather than a descriptor or dynamic lookup. This proves access-path
    /// stability between effects, not global heap singleton ownership.
    fn field_access_is_plain(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _class: &ClassIdentity,
        _member: &str,
    ) -> bool {
        false
    }

    /// Whether reading or writing this instance member may use a class
    /// descriptor instead of ordinary instance storage. A positive answer
    /// excludes the member from field-slot propagation; reads remain an
    /// explicit unknown. Adapters should also return true when the declaration
    /// needed to rule out descriptor behavior is unresolved.
    fn field_access_may_use_descriptor(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _class: &ClassIdentity,
        _member: &str,
    ) -> bool {
        false
    }

    fn dynamic_field_writes(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
    ) -> Vec<DynamicFieldWrite> {
        Vec::new()
    }

    /// A structured upper bound for a dynamic write's receiver when the IR
    /// cannot observe that receiver directly, such as `self.__dict__.update`
    /// or `super().__setattr__`. The flow engine validates the returned class
    /// hierarchy before using it to scope the write.
    fn dynamic_write_receiver_bound(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _write_span: SourceSpan,
    ) -> Option<ClassIdentity> {
        None
    }

    /// A stable instance field whose loaded value is the receiver of this
    /// dynamic write, such as `setattr(self.cell_class, name, value)`. The
    /// flow engine uses the field-slot index to inspect every store to that
    /// field before deriving a receiver bound.
    fn dynamic_write_receiver_field(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _write_span: SourceSpan,
    ) -> Option<(ClassIdentity, Box<str>)> {
        None
    }

    /// Class bounds for a source site retained by a field slot. `Ok(None)`
    /// means the site is not a store to `member` (for example, an incomplete
    /// slot witness at a load); `Ok(Some(bounds))` means it is such a store,
    /// and an empty bound is a value excluded from every static class atom.
    /// An error marks a recognized store whose value remains unbounded.
    fn field_store_value_bounds(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _file: &ProjectFile,
        _span: SourceSpan,
        _member: &str,
    ) -> Result<Option<Vec<ClassIdentity>>, UnknownReason> {
        Ok(None)
    }

    /// Whether a dynamic write's receiver annotation explicitly permits any
    /// runtime class, such as an unbounded type parameter or `Any`.
    fn dynamic_write_receiver_is_explicitly_unbounded(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _write_span: SourceSpan,
    ) -> bool {
        false
    }

    /// A complete static-class receiver bound proved from the receiver
    /// expression of one arbitrary-name dynamic write. An empty vector means
    /// the receiver is provably a runtime-created class or instance, whose
    /// exact runtime class is distinct from every static class atom. `Ok(None)`
    /// means this rule does not apply; `Err(reason)` means a recognized shape
    /// has unresolved receiver information, so the effect stays global.
    fn dynamic_type_write_receiver_bounds(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _receiver: ValueId,
        _write_span: SourceSpan,
    ) -> Result<Option<Vec<ClassIdentity>>, UnknownReason> {
        Ok(None)
    }

    /// Complete static-class receiver bounds for a parameter of a nested
    /// function whose name is used only as a direct callee in its enclosing
    /// function. Every call-site argument must be bounded. An empty vector
    /// means all arguments are proved runtime-created values. `Ok(None)` means
    /// this rule does not apply; `Err(reason)` means the nested parameter is
    /// escaping or has at least one unbounded call-site argument.
    fn non_escaping_nested_write_receiver_bounds(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _receiver: ValueId,
        _write_span: SourceSpan,
    ) -> Result<Option<Vec<ClassIdentity>>, UnknownReason> {
        Ok(None)
    }

    /// Classify each candidate on the guard's true arm, in input order.
    /// Resolve guard operands once for the batch. The false arm reverses
    /// Keep and Drop; Unknown remains on both arms without a reason, while
    /// Incomplete remains on both arms and contributes its reason on the true
    /// edge. Member lookup is
    /// supplied by the flow engine so declaration-only absence can consult
    /// the same workspace store survey as final member interpretation.
    fn narrowing_verdicts(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _guard: &GuardFact,
        atoms: &[&ClassIdentity],
        _member_lookup: &dyn Fn(&ClassIdentity, &str) -> MemberLookup,
    ) -> Vec<NarrowingVerdict> {
        vec![NarrowingVerdict::Unknown; atoms.len()]
    }

    /// What the guard's true arm proves about a value the class-set domain
    /// could not name.
    ///
    /// [`narrowing_verdicts`](Self::narrowing_verdicts) classifies candidates
    /// the engine already named, and an `Unknown` atom is not a class: it has
    /// no hierarchy to test, so narrowing alone carries a remainder into an
    /// arm that has already established what the value is. A predicate that
    /// does establish it answers here, in the same seed vocabulary the other
    /// adapter answers use, and the engine replaces the remainder on the true
    /// arm with this seed. Answer the exact class set only when the check is
    /// closed; a check a subclass also satisfies names its classes with an
    /// open bound, because the subclass's member surface is not the named
    /// class's. The default, `NotApplicable`, says the true arm proves no
    /// class and the remainder is carried through unchanged.
    fn guard_proves_classes(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _guard: &GuardFact,
    ) -> ClassSeed {
        ClassSeed::NotApplicable
    }

    /// Every value [`call_guard_narrowing`](Self::call_guard_narrowing) and
    /// [`normal_return_type_constraints`](Self::normal_return_type_constraints)
    /// can name as a subject in `procedure`.
    ///
    /// Binding refinement carries temporal-identity state only for the values
    /// a consumer can ask about, so an implementation that names a value
    /// outside this set asks about state that was never carried. Both methods
    /// constrain an actual argument of a call, so the default answer is every
    /// call-site argument. An adapter that recognizes fewer calls should say
    /// so here; the answer is a promise, and the consumer checks it.
    fn refinement_subjects(
        &self,
        _workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
    ) -> Vec<ValueId> {
        procedure
            .semantics()
            .call_sites()
            .iter()
            .flat_map(|call| call.arguments.iter().map(|argument| argument.value))
            .collect()
    }

    /// Derive a guard from an exactly resolved predicate call.
    /// Implementations must validate the current body and callable binding.
    /// A resolved, modeled predicate reports `Narrowed` with the constrained
    /// actual argument and one verdict per candidate. A predicate call whose
    /// callee cannot be modeled reports `Unmodeled` with that argument: the
    /// developer's condition says something about the value that the engine
    /// cannot name, which is true on both arms. Anything else reports
    /// `NoConstraint`. These query-local facts become ordinary edge kills,
    /// whose behavior is summary-keyed.
    fn call_guard_narrowing(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _guard: &GuardFact,
        _atoms: &[&ClassIdentity],
        _member_lookup: &dyn Fn(&ClassIdentity, &str) -> MemberLookup,
    ) -> CallGuardOutcome {
        CallGuardOutcome::NoConstraint
    }

    /// Return only contracts whose target, actual/formal binding, and class
    /// arguments are established from structured evidence. An unresolved,
    /// overridden, rebound, or conflicting invocation has no constraint.
    fn normal_return_type_constraints(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _call: &SemanticCallSite,
    ) -> Vec<NormalReturnTypeConstraint> {
        Vec::new()
    }

    fn instance_of_verdict(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _atom: &ClassIdentity,
        _classes: &[ClassIdentity],
    ) -> NarrowingVerdict {
        NarrowingVerdict::Unknown
    }
}

/// The class-set adapter `language` registers, or `None` when its language
/// support reports none. This is the public enumeration point for engines in
/// sibling crates; `LanguageSupport::type_flow_adapter` stays crate-internal.
pub fn type_flow_adapter(language: Language) -> Option<&'static dyn TypeFlowAdapter> {
    language_support_for_hook(language, "type_flow_adapter")
        .and_then(|support| support.type_flow_adapter())
}
