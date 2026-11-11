//! Selected, query-local Go hierarchy support.
//!
//! A declaration's local support is separate from the completeness of an
//! ancestor or descendant enumeration. The latter can depend on other files.
use super::*;
use crate::analyzer::resolution::{
    DeferredMemberOwnerLookupName, GoMethodSatisfaction, LoweredDeferredMemberOwner,
    ResolutionBatchMetrics, SelectedTypedRow, TypedFactPageVisitor, TypedFactRequest,
};
use crate::analyzer::store::resolution::TypedFactRelation;
use brokk_bifrost_core::analyzer::resolution_facts::{
    IntrinsicTypeKind, ResolutionGapKind, ResolutionMemberKind,
};
use rusqlite::{OptionalExtension, params};

#[cfg(any(test, feature = "test-support"))]
mod hierarchy_preparation_stop_probe {
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;
    use brokk_bifrost_core::analyzer::usages::resolution_session::{
        BoundedResolution, ResolutionSession,
    };
    use std::cell::Cell;

    thread_local! {
        static ARMED: Cell<bool> = const { Cell::new(false) };
        static FIRED: Cell<Option<ReceiverBudgetLimit>> = const { Cell::new(None) };
    }

    pub(super) fn arm() {
        assert!(
            !ARMED.replace(true),
            "hierarchy preparation probe already armed"
        );
        FIRED.set(None);
    }
    pub(super) fn fire(session: &ResolutionSession) {
        if ARMED.replace(false) {
            assert!(!session.scope_steps(usize::MAX));
            let BoundedResolution::Exceeded { limit, .. } = session.finish(()) else {
                panic!("hierarchy preparation probe did not latch a stop");
            };
            FIRED.set(Some(limit));
        }
    }
    pub(super) fn fired_limit() -> Option<ReceiverBudgetLimit> {
        FIRED.get()
    }
    pub(super) fn clear() {
        ARMED.set(false);
        FIRED.set(None);
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct GoHierarchyPreparationStopProbe(std::marker::PhantomData<std::rc::Rc<()>>);

#[cfg(any(test, feature = "test-support"))]
impl GoHierarchyPreparationStopProbe {
    pub fn arm() -> Self {
        hierarchy_preparation_stop_probe::arm();
        Self(std::marker::PhantomData)
    }
    pub fn fired_limit(
        &self,
    ) -> Option<brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit> {
        hierarchy_preparation_stop_probe::fired_limit()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Drop for GoHierarchyPreparationStopProbe {
    fn drop(&mut self) {
        let unused = hierarchy_preparation_stop_probe::fired_limit().is_none();
        hierarchy_preparation_stop_probe::clear();
        if !std::thread::panicking() {
            assert!(!unused, "hierarchy preparation stop probe was not consumed");
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
mod forward_proof_stop_probe {
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;
    use brokk_bifrost_core::analyzer::usages::resolution_session::{
        BoundedResolution, ResolutionSession,
    };
    use std::cell::Cell;

    thread_local! {
        static ACTIVE: Cell<bool> = const { Cell::new(false) };
        static ARMED: Cell<bool> = const { Cell::new(false) };
        static FIRED: Cell<Option<ReceiverBudgetLimit>> = const { Cell::new(None) };
    }

    pub(super) fn arm() {
        ACTIVE.with(|active| {
            assert!(
                !active.replace(true),
                "forward proof stop probe guard already active"
            )
        });
        ARMED.with(|armed| {
            assert!(
                !armed.replace(true),
                "forward proof stop probe already armed"
            )
        });
        FIRED.set(None);
    }

    pub(super) fn fire_after_complete_embeddings(session: &ResolutionSession) {
        if ARMED.replace(false) {
            assert!(!session.scope_steps(usize::MAX));
            let BoundedResolution::Exceeded { limit, .. } = session.finish(()) else {
                panic!("forward proof probe did not latch a budget stop");
            };
            FIRED.set(Some(limit));
        }
    }

    pub(super) fn fired_limit() -> Option<ReceiverBudgetLimit> {
        FIRED.get()
    }
    pub(super) fn clear() {
        ACTIVE.set(false);
        ARMED.set(false);
        FIRED.set(None);
    }
    pub(super) fn unused() -> bool {
        ARMED.get()
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct GoForwardProofStopProbe(std::marker::PhantomData<std::rc::Rc<()>>);

#[cfg(any(test, feature = "test-support"))]
impl GoForwardProofStopProbe {
    pub fn arm() -> Self {
        forward_proof_stop_probe::arm();
        Self(std::marker::PhantomData)
    }

    pub fn fired_limit(
        &self,
    ) -> Option<brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit> {
        forward_proof_stop_probe::fired_limit()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Drop for GoForwardProofStopProbe {
    fn drop(&mut self) {
        let unused = forward_proof_stop_probe::unused();
        forward_proof_stop_probe::clear();
        if !std::thread::panicking() {
            assert!(!unused, "forward proof stop probe was not consumed");
        }
    }
}

#[derive(Debug)]
pub struct GoDirectSupertype {
    pub origin: GoSupertypeOrigin,
    pub targets: Vec<SemanticId>,
    pub completion: ResolutionCompletion,
    pub open_reason: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoSupertypeOrigin {
    Embedding { reference: SemanticId },
    UnresolvedEmbedding,
    Structural,
}

/// Names are nomination seeds only. The selected satisfaction proof decides
/// membership, including receiver form and promoted-method shadowing.
static GO_OWNER_METHOD_NAMES_SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!(
        r#"WITH RECURSIVE root AS (
          SELECT declaration.blob_id,declaration.type_id,declaration.name,file.package_id
          FROM temp.selected_resolution_mounts mount
          JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=mount.mount_ordinal
          JOIN main.resolution_semantic_sites semantic ON semantic.blob_id=mount.blob_id
            AND semantic.semantic_key=?2 AND semantic.semantic_role='definition'
          JOIN main.source_native_declaration_bridges bridge ON bridge.blob_id=semantic.blob_id
            AND bridge.source_site=semantic.source_site
          JOIN main.source_go_type_declarations declaration ON declaration.blob_id=bridge.blob_id
            AND declaration.declaration_id=bridge.declaration_id
          JOIN ({}) file ON file.file_version_id=coalesce(mount.file_version_id,
            (SELECT placement.file_version_id FROM temp.selected_go_transient_placements placement
             WHERE placement.mount_ordinal=mount.mount_ordinal))
            AND file.context_id=?3 AND file.source_role IN ('go',?4)
          WHERE mount.mount_ordinal=?1 AND mount.storage_language='go'
        ), peers AS (
          SELECT mount.mount_ordinal,mount.blob_id
          FROM temp.selected_resolution_mounts mount
          JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=mount.mount_ordinal
          JOIN ({}) file ON file.file_version_id=coalesce(mount.file_version_id,
            (SELECT placement.file_version_id FROM temp.selected_go_transient_placements placement
             WHERE placement.mount_ordinal=mount.mount_ordinal))
            AND file.context_id=?3 AND file.source_role IN ('go',?4)
          JOIN root ON root.package_id=file.package_id
          WHERE mount.storage_language='go'
        ), receivers(mount_ordinal,blob_id,declaration_id,type_id) AS (
          SELECT peer.mount_ordinal,peer.blob_id,callable.declaration_id,callable.receiver_type_id
          FROM peers peer JOIN main.source_go_callables callable ON callable.blob_id=peer.blob_id
          WHERE callable.is_method=1 AND callable.receiver_type_id IS NOT NULL
          UNION
          SELECT receiver.mount_ordinal,receiver.blob_id,receiver.declaration_id,type.child1
          FROM receivers receiver JOIN main.source_go_types type ON type.blob_id=receiver.blob_id
            AND type.type_id=receiver.type_id WHERE type.child1 IS NOT NULL
        )
        SELECT callable.name FROM peers peer
        JOIN main.source_go_callables callable ON callable.blob_id=peer.blob_id
        JOIN root ON 1=1
        WHERE callable.is_method=1 AND (
          (callable.blob_id=root.blob_id AND callable.owner_type_id=root.type_id)
          OR EXISTS (SELECT 1 FROM receivers receiver
            JOIN main.source_go_type_names receiver_name ON receiver_name.blob_id=receiver.blob_id
              AND receiver_name.type_id=receiver.type_id
            WHERE receiver.mount_ordinal=peer.mount_ordinal
              AND receiver.blob_id=callable.blob_id
              AND receiver.declaration_id=callable.declaration_id
              AND receiver_name.name=root.name))
        ORDER BY callable.name"#,
        super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str(),
        super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str(),
    )
});

static GO_SELECTED_INTERFACES_SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!(
        r#"SELECT mount.mount_ordinal,semantic.semantic_key,type.has_named_children,
          EXISTS(SELECT 1 FROM main.source_go_callables callable
            WHERE callable.blob_id=type.blob_id AND callable.owner_type_id=type.type_id
              AND callable.is_method=1)
        FROM temp.selected_resolution_mounts mount
        JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=mount.mount_ordinal
        JOIN main.source_go_type_declarations declaration ON declaration.blob_id=mount.blob_id
        LEFT JOIN main.source_go_types type ON type.blob_id=declaration.blob_id
          AND type.type_id=declaration.type_id
        JOIN main.source_native_declaration_bridges bridge ON bridge.blob_id=declaration.blob_id
          AND bridge.declaration_id=declaration.declaration_id
        JOIN main.resolution_semantic_sites semantic ON semantic.blob_id=bridge.blob_id
          AND semantic.source_site=bridge.source_site AND semantic.semantic_role='definition'
        JOIN ({}) file ON file.file_version_id=coalesce(mount.file_version_id,
          (SELECT placement.file_version_id FROM temp.selected_go_transient_placements placement
           WHERE placement.mount_ordinal=mount.mount_ordinal))
          AND file.context_id=?1 AND file.source_role IN ('go',?2)
        WHERE mount.storage_language='go' AND (type.kind=13 OR type.type_id IS NULL)
        ORDER BY mount.mount_ordinal,semantic.semantic_key"#,
        super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str()
    )
});

// Selected named aliases need terminal binding proof. Inline interface aliases
// have no declaration row in GO_SELECTED_INTERFACES_SQL and remain open until
// their inventories can be enumerated through the selected alias projection.
static GO_SELECTED_ALIASES_SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!(
        r#"SELECT alias.blob_id,alias.target_type_id,mount.mount_ordinal
            FROM temp.selected_resolution_mounts mount
            JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=mount.mount_ordinal
            JOIN main.source_go_aliases alias ON alias.blob_id=mount.blob_id
            JOIN ({}) file ON file.file_version_id=coalesce(mount.file_version_id,
              (SELECT placement.file_version_id FROM temp.selected_go_transient_placements placement
               WHERE placement.mount_ordinal=mount.mount_ordinal))
              AND file.context_id=?1 AND file.source_role IN ('go',?2)
            WHERE mount.storage_language='go'"#,
        super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str()
    )
});

static GO_ALIAS_INTERFACE_HEAD_SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!(
        r#"{} SELECT
          EXISTS(SELECT 1 FROM head JOIN main.source_go_types ty
            ON ty.blob_id=head.blob_id AND ty.type_id=head.type_id
            WHERE ty.kind=13 AND head.pointer_hops=0),
          EXISTS(SELECT 1 FROM head JOIN main.source_go_types ty
            ON ty.blob_id=head.blob_id AND ty.type_id=head.type_id
            WHERE ty.kind=0 AND head.pointer_hops=0),
          EXISTS(SELECT 1 FROM head JOIN main.source_go_types ty
            ON ty.blob_id=head.blob_id AND ty.type_id=head.type_id
            WHERE head.depth>={GO_SOURCE_TYPE_HEAD_DEPTH} AND ty.kind IN (1,7,8)),
          EXISTS(SELECT 1 FROM head
            LEFT JOIN main.source_go_types ty
              ON ty.blob_id=head.blob_id AND ty.type_id=head.type_id
            WHERE ty.type_id IS NULL OR ty.kind NOT BETWEEN 0 AND 14
              OR ty.kind IN (9,10,11,14)
              OR (ty.kind IN (1,7) AND ty.child1 IS NULL)
              OR (ty.kind=8 AND (
                NOT EXISTS (SELECT 1 FROM main.source_go_type_children child
                  WHERE child.blob_id=ty.blob_id AND child.type_id=ty.type_id
                    AND child.ordinal=0)
                OR EXISTS (SELECT 1 FROM main.source_go_type_children sibling
                  WHERE sibling.blob_id=ty.blob_id AND sibling.type_id=ty.type_id
                    AND sibling.ordinal>0))))"#,
        go_source_type_head_sql("SELECT ?1 AS blob_id,?2 AS type_id,0 AS depth", None)
    )
});

/// Expected context placements lead this read; a missing mount must remain a
/// row. The mount's content identity, not its predecessor placement, is what
/// the Go source admission subsequently checks.
static GO_FORWARD_CENSUS_SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!(
        r#"SELECT package.package_id, package.complete, file.file_version_id,
                 mount.mount_ordinal, mount.blob_id, mount.blob_oid, mount.generation,
                 scope.mount_ordinal
          FROM main.go_package_instances package
          LEFT JOIN ({}) file ON file.package_id=package.package_id
            AND file.context_id=?1 AND file.source_role IN ('go',?2)
          LEFT JOIN temp.selected_resolution_mounts mount
            ON mount.storage_language='go' AND file.file_version_id=coalesce(
              mount.file_version_id,
              (SELECT placed.file_version_id FROM temp.selected_go_transient_placements placed
               WHERE placed.mount_ordinal=mount.mount_ordinal))
          LEFT JOIN temp.selected_resolution_scope_mounts scope
            ON scope.mount_ordinal=mount.mount_ordinal
          WHERE package.context_id=?1 AND package.provider_kind='workspace'
            AND (?3 IS NULL OR package.package_id=?3)
          ORDER BY package.package_id,file.file_version_id,mount.mount_ordinal"#,
        super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str()
    )
});

#[derive(Debug)]
pub struct GoDirectSupertypeAnswer {
    pub parents: Vec<GoDirectSupertype>,
    pub open_reasons: Vec<&'static str>,
    pub forward_open_reasons: Vec<&'static str>,
    /// Whether the interfaces this type satisfies structurally, without
    /// embedding them, were enumerated under the selected context and role.
    /// All candidate, inventory, publication and stop obligations must close.
    pub forward_satisfaction_enumerated: bool,
}

/// One selected (context, role) empty-interface scan. The owning walk keeps
/// this alongside its captured read receipt; no store-global cache retains it.
#[derive(Debug)]
pub struct GoForwardEmptyInterfaceScan {
    context_id: i64,
    source_role: String,
    empty: Vec<SemanticId>,
    open_reasons: Vec<&'static str>,
    complete: bool,
}

impl GoForwardEmptyInterfaceScan {
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn has_open_reasons(&self) -> bool {
        !self.open_reasons.is_empty()
    }
}

#[derive(Debug)]
pub struct GoDirectSubtypeAnswer {
    pub edges: Vec<SemanticId>,
    pub ambiguous: Vec<SemanticId>,
    pub open: Vec<SemanticId>,
    pub open_reasons: Vec<&'static str>,
    pub read_keys: GoHierarchyReadKeys,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GoHierarchyCoverageReadKey {
    pub context_id: i64,
    pub selection_fingerprint: [u8; 32],
}

#[derive(Debug, Default)]
pub struct GoHierarchyReadKeys {
    pub coverage: Option<GoHierarchyCoverageReadKey>,
    pub names: Vec<crate::analyzer::store::resolution_typed::GoLookupReadKey>,
}

#[derive(Debug, Default)]
pub struct GoMethodFamilyDirection {
    pub methods: Vec<SemanticId>,
    pub open_reasons: Vec<&'static str>,
    pub read_keys: GoHierarchyReadKeys,
}

impl GoMethodFamilyDirection {
    pub fn is_complete(&self) -> bool {
        self.open_reasons.is_empty()
    }
}

#[derive(Debug, Default)]
pub struct GoNativeMethodFamilyAnswer {
    pub implements: GoMethodFamilyDirection,
    pub implemented_by: GoMethodFamilyDirection,
}

struct GoEmbeddingClosure {
    answer: GoDirectSubtypeAnswer,
    completed: std::collections::HashMap<
        crate::analyzer::resolution::ResolutionTypeRef,
        crate::analyzer::resolution::fact_resolution::go_methods::GoTypeSatisfaction,
    >,
}

struct GoMethodContract {
    lookup: SemanticId,
    interface: SemanticId,
}

impl GoDirectSubtypeAnswer {
    pub fn is_complete(&self) -> bool {
        self.open.is_empty() && self.open_reasons.is_empty()
    }
}

impl GoDirectSupertypeAnswer {
    pub fn is_complete(&self) -> bool {
        self.forward_satisfaction_enumerated && self.embeddings_complete()
    }

    /// Completeness of the embedded parents alone.
    pub fn embeddings_complete(&self) -> bool {
        self.open_reasons.is_empty()
            && self
                .parents
                .iter()
                .all(|parent| parent.open_reason.is_none())
    }
}

/// Authority for one selected Go type declaration. An alias needs a separate
/// target proof before it can be used as a hierarchy endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GoTypeSupport {
    Supported,
    Unsupported,
    Open,
}

enum GoAliasTerminal {
    Selected(SemanticId),
    Primitive,
}

impl SelectedResolutionOperation<'_, '_> {
    fn go_hierarchy_method_identity(
        &self,
        context_id: i64,
        source_role: &str,
        method: SemanticId,
    ) -> Result<Option<(String, i64)>> {
        let (Some(mount), Some(key)) = (method.ordinal(), method.local_key()) else {
            return Ok(None);
        };
        self.ready
            .inventory
            .connection()
            .prepare_cached(GO_HIERARCHY_METHOD_IDENTITY_SQL.as_str())?
            .query_row(params![mount, key, context_id, source_role], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()
            .map_err(Into::into)
    }

    /// Return selected method identities for both directions. Each direction
    /// closes independently; an incomplete inverse never certifies absence.
    pub fn go_native_method_family(
        &self,
        context_id: i64,
        source_role: &str,
        method: SemanticId,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<GoNativeMethodFamilyAnswer> {
        let mut answer = GoNativeMethodFamilyAnswer::default();
        let coverage_key = GoHierarchyCoverageReadKey {
            context_id,
            selection_fingerprint: self.ready.inventory.fingerprint(),
        };
        answer.implements.read_keys.coverage = Some(coverage_key);
        answer.implemented_by.read_keys.coverage = Some(coverage_key);
        if let Some(reason) = self
            .go_hierarchy_selection_coverage(context_id, source_role)?
            .incomplete_reason()
        {
            answer.implements.open_reasons.push(reason);
            answer.implemented_by.open_reasons.push(reason);
        }
        if cancellation.is_cancelled() || !session.scope_steps(1) {
            answer
                .implements
                .open_reasons
                .push("method family cancelled or exhausted its budget");
            answer
                .implemented_by
                .open_reasons
                .push("method family cancelled or exhausted its budget");
            return Ok(answer);
        }
        let Some((name, _)) = self.go_hierarchy_method_identity(context_id, source_role, method)?
        else {
            answer
                .implements
                .open_reasons
                .push("method has no selected Go declaration identity");
            answer
                .implemented_by
                .open_reasons
                .push("method has no selected Go declaration identity");
            return Ok(answer);
        };
        let lookup = self.go_static_member_lookup(&name);
        let typed = self.ready.typed_source();
        let Some(keys) = typed.go_lookup_read_keys(
            &[lookup],
            TypedFactRelation::InterfaceMethodLookup,
            cancellation,
        )?
        else {
            answer
                .implements
                .open_reasons
                .push("interface method lookup was cancelled");
            answer
                .implemented_by
                .open_reasons
                .push("interface method lookup was cancelled");
            return Ok(answer);
        };
        answer
            .implements
            .read_keys
            .names
            .extend(keys.iter().copied());
        answer.implemented_by.read_keys.names.extend(keys);
        let mut nominations = Vec::new();
        let mut stopped = false;
        let mut callback =
            |page: &[crate::analyzer::store::resolution_typed::GoLookupCandidate]| {
                if cancellation.is_cancelled() || !session.scope_steps(1) {
                    stopped = true;
                    return Ok(false);
                }
                nominations.extend_from_slice(page);
                Ok(true)
            };
        let outcome = typed.visit_go_interface_method_candidate_pages(
            &[lookup],
            cancellation,
            &mut TypedFactPageVisitor::new(&mut callback),
        )?;
        if stopped || !outcome.is_exhausted() || cancellation.is_cancelled() {
            answer
                .implements
                .open_reasons
                .push("interface method seek cancelled or exhausted its budget");
        }
        let connection = self.ready.inventory.connection();
        let mut interfaces = Vec::new();
        for nomination in nominations {
            if cancellation.is_cancelled() || !session.scope_steps(1) {
                answer
                    .implements
                    .open_reasons
                    .push("interface method confirmation cancelled or exhausted its budget");
                break;
            }
            let role = self.go_source_role_for_mount(context_id, nomination.mount, cancellation)?;
            let Some(role) = role else {
                answer
                    .implements
                    .open_reasons
                    .push("interface candidate source role is unavailable");
                continue;
            };
            if role != "go" && role != source_role {
                continue;
            }
            let mut statement =
                connection.prepare_cached(GO_METHOD_INTERFACE_OWNERS_SQL.as_str())?;
            let owners = statement
                .query_map(
                    params![
                        nomination.mount.get(),
                        nomination.blob_id,
                        &name,
                        context_id,
                        source_role
                    ],
                    |row| row.get::<_, u32>(0),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            interfaces.extend(
                owners
                    .into_iter()
                    .map(|key| SemanticId::local(nomination.mount.get(), key)),
            );
        }
        interfaces.sort_unstable();
        interfaces.dedup();
        for interface in interfaces {
            if cancellation.is_cancelled() || !session.scope_steps(1) {
                answer
                    .implements
                    .open_reasons
                    .push("interface satisfaction cancelled or exhausted its budget");
                break;
            }
            let Some(outcomes) = self.go_candidate_method_satisfaction(
                context_id,
                source_role,
                method,
                GoMethodContract { lookup, interface },
                cancellation,
                session,
            )?
            else {
                answer
                    .implements
                    .open_reasons
                    .push("interface satisfaction context is unavailable");
                continue;
            };
            let mut seeds = Vec::new();
            let mut interface_methods = Vec::new();
            let mut direct_satisfies = false;
            for outcome in outcomes {
                seeds.extend(
                    outcome
                        .candidate_receivers
                        .iter()
                        .map(|receiver| receiver.identity()),
                );
                interface_methods.extend(outcome.methods.iter().copied());
                match outcome.outcome {
                    GoMethodSatisfaction::Satisfies => {
                        direct_satisfies = true;
                        answer.implements.methods.extend(outcome.methods)
                    }
                    GoMethodSatisfaction::Inconclusive(reason) => {
                        answer.implements.open_reasons.push(reason)
                    }
                    GoMethodSatisfaction::DoesNotSatisfy => {}
                }
            }
            seeds.sort_unstable();
            seeds.dedup();
            interface_methods.sort_unstable();
            interface_methods.dedup();
            // Either a direct proof already selected the queried method, or no
            // method of this interface matches the lookup.
            if direct_satisfies || interface_methods.is_empty() {
                continue;
            }
            // A direct owner that does not satisfy the interface on its own can
            // still implement it through a type that embeds it, so the negative
            // is complete only after the embedding closure finds no such proof.
            if seeds.is_empty() {
                answer
                    .implements
                    .open_reasons
                    .push("method receiver frontier is unavailable");
            } else {
                let closure = self.go_close_satisfying_embeddings(
                    context_id,
                    source_role,
                    interface,
                    None,
                    &seeds,
                    &[0, 1],
                    cancellation,
                    session,
                )?;
                answer
                    .implements
                    .read_keys
                    .names
                    .extend(closure.answer.read_keys.names);
                answer
                    .implements
                    .open_reasons
                    .extend(closure.answer.open_reasons);
                let promoted = closure.completed.into_values().any(|result| {
                    result.outcome == GoMethodSatisfaction::Satisfies
                        && result
                            .selections
                            .iter()
                            .any(|&(name, selected)| name == lookup && selected == method)
                });
                if promoted {
                    // The promoted proof selects the queried method, but it
                    // does not associate each earlier formal ID with that
                    // selection. Those IDs include negative or inconclusive
                    // outcomes, so none can be published from this proof.
                    answer
                        .implements
                        .open_reasons
                        .push("promoted method selection does not certify earlier formal IDs");
                }
            }
        }

        answer.implements.methods.sort_unstable();
        answer.implements.methods.dedup();
        answer
            .implements
            .methods
            .retain(|candidate| *candidate != method);

        let (Some(ordinal), Some(key)) = (method.ordinal(), method.local_key()) else {
            return Ok(answer);
        };
        let owner: Option<u32> = connection
            .prepare_cached(GO_INTERFACE_OWNER_FOR_METHOD_SQL.as_str())?
            .query_row(params![ordinal, key, context_id, source_role], |row| {
                row.get(0)
            })
            .optional()?;
        let Some(owner) = owner else {
            if cancellation.is_cancelled() || !session.scope_steps(1) {
                answer
                    .implemented_by
                    .open_reasons
                    .push("method family cancelled or exhausted its budget");
                return Ok(answer);
            }
            let anonymous_interface_method: bool = connection
                .prepare_cached(GO_ANONYMOUS_INTERFACE_METHOD_SQL)?
                .query_row(params![ordinal, key], |row| row.get(0))?;
            if cancellation.is_cancelled() || !session.observe_cancellation() {
                answer
                    .implemented_by
                    .open_reasons
                    .push("method family cancelled or exhausted its budget");
                return Ok(answer);
            }
            if anonymous_interface_method {
                answer
                    .implemented_by
                    .open_reasons
                    .push("interface method has no declaring interface identity");
            }
            return Ok(answer);
        };
        let interface = SemanticId::local(ordinal, owner);
        // Interface methods describe contracts, not executable implementations.
        // Type satisfaction still uses interface receivers in the hierarchy path.
        answer.implements.methods.clear();
        let (satisfaction, seeds) = self.go_satisfying_receivers_for_lookup(
            context_id,
            source_role,
            GoMethodContract { lookup, interface },
            &name,
            cancellation,
            session,
        )?;
        let mut owners = seeds
            .iter()
            .map(|receiver| receiver.identity())
            .collect::<Vec<_>>();
        owners.sort_unstable();
        owners.dedup();
        let closure = self.go_close_satisfying_embeddings(
            context_id,
            source_role,
            interface,
            None,
            &owners,
            &[0, 1],
            cancellation,
            session,
        )?;
        let GoEmbeddingClosure {
            answer: closure,
            completed,
        } = closure;
        answer
            .implemented_by
            .read_keys
            .names
            .extend(satisfaction.read_keys.names);
        answer
            .implemented_by
            .read_keys
            .names
            .extend(closure.read_keys.names);
        answer
            .implemented_by
            .open_reasons
            .extend(satisfaction.open_reasons);
        answer
            .implemented_by
            .open_reasons
            .extend(closure.open_reasons);
        // Consume proofs in a fixed order so a budget stop cuts the same
        // subset on every run.
        let mut completed = completed.into_iter().collect::<Vec<_>>();
        completed
            .sort_unstable_by_key(|(receiver, _)| (receiver.identity(), receiver.indirection()));
        // Only a method of a non-interface receiver can execute a call, so an
        // interface that satisfies this one, directly or through embedding,
        // contributes no member edge. Legacy Go records the same pairs.
        let mut receivers = completed
            .iter()
            .map(|(receiver, _)| receiver.identity())
            .collect::<Vec<_>>();
        receivers.dedup();
        let receiver_kinds = if receivers.is_empty() {
            Some(HashMap::default())
        } else {
            self.ready
                .typed_source()
                .go_member_declarations(&receivers, cancellation)?
                .map(|declarations| {
                    declarations
                        .into_iter()
                        .map(|declaration| {
                            let interface = matches!(
                                declaration.kind,
                                crate::analyzer::resolution::GoMemberDeclarationKind::Interface { .. }
                            );
                            (declaration.definition, interface)
                        })
                        .collect::<HashMap<_, _>>()
                })
        };
        let Some(receiver_kinds) = receiver_kinds else {
            answer
                .implemented_by
                .open_reasons
                .push("method receiver kind is unavailable");
            return Ok(answer);
        };
        for (receiver, result) in completed {
            if cancellation.is_cancelled() || !session.scope_steps(1) {
                answer
                    .implemented_by
                    .open_reasons
                    .push("method selection cancelled or exhausted its budget");
                break;
            }
            match receiver_kinds.get(&receiver.identity()) {
                Some(false) => {}
                Some(true) => continue,
                None => {
                    answer
                        .implemented_by
                        .open_reasons
                        .push("method receiver kind is unavailable");
                    continue;
                }
            }
            answer.implemented_by.methods.extend(
                result
                    .selections
                    .into_iter()
                    .filter(|(selected_name, _)| *selected_name == lookup)
                    .map(|(_, selected)| selected),
            );
        }
        answer.implemented_by.methods.sort_unstable();
        answer.implemented_by.methods.dedup();
        answer
            .implemented_by
            .methods
            .retain(|candidate| *candidate != method);
        Ok(answer)
    }

    fn with_go_hierarchy_forward<T>(
        &self,
        context_id: i64,
        source_role: &str,
        owner: SemanticId,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
        run: impl FnOnce(&mut crate::analyzer::resolution::FactResolutionOperation<'_>) -> Result<T>,
    ) -> Result<Option<T>> {
        let Some(ordinal) = owner.ordinal() else {
            return Ok(None);
        };
        let mount = self
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let path = mount.persisted_relative_path();
        let prepared = match self.go_file_import_context_with_role(
            context_id,
            path,
            source_role,
            cancellation,
        )? {
            GoPreparedImportContextOutcome::Ready(prepared) => *prepared,
            GoPreparedImportContextOutcome::Cancelled
            | GoPreparedImportContextOutcome::Unavailable => return Ok(None),
        };
        let context = match self.prepare_context(
            prepared.context,
            cancellation,
            &SelectedResolutionContextMetrics,
        )? {
            SelectedResolutionContextValidationOutcome::Ready(context) => context,
            SelectedResolutionContextValidationOutcome::Cancelled => return Ok(None),
        };
        #[cfg(any(test, feature = "test-support"))]
        hierarchy_preparation_stop_probe::fire(session);
        if cancellation.is_cancelled() || !session.observe_cancellation() {
            return Ok(None);
        }
        let Some(blueprint) = self.ready.publish_prepared_context(
            context,
            cancellation,
            session,
            Some(&self.jvm_context_blueprints),
            |blueprint| {
                if cancellation.is_cancelled() || !session.observe_cancellation() {
                    return Ok(ContextRegistrationOutcome::Cancelled);
                }
                self.ready.register_context(blueprint, cancellation)
            },
        )?
        else {
            return Ok(None);
        };
        if cancellation.is_cancelled() || !session.observe_cancellation() {
            return Ok(None);
        }
        let lexical = self.ready.lexical_source();
        let typed = self.ready.typed_source();
        let lexical = SeamProfiled::observing(&lexical);
        let typed = SeamProfiled::observing(&typed);
        self.with_go_forward_operation(
            GoForwardOperationContext {
                blueprint: &blueprint,
                demand: prepared.demand,
                caller_path: path,
                lexical: &lexical,
                typed: &typed,
                cancellation,
                session,
            },
            None,
            run,
        )
        .map(Some)
    }

    fn go_interface_method_inventory(
        &self,
        context_id: i64,
        source_role: &str,
        owner: SemanticId,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<
        Option<
            crate::analyzer::resolution::fact_resolution::go_methods::GoInterfaceMethodInventory,
        >,
    > {
        Ok(self
            .with_go_hierarchy_forward(
                context_id,
                source_role,
                owner,
                cancellation,
                session,
                |forward| forward.go_interface_method_inventory(owner),
            )?
            .flatten())
    }

    fn go_candidate_method_satisfaction(
        &self,
        context_id: i64,
        visible_role: &str,
        method: SemanticId,
        contract: GoMethodContract,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<Option<Vec<crate::analyzer::resolution::GoInterfaceSatisfaction>>> {
        let Some(ordinal) = method.ordinal() else {
            return Ok(None);
        };
        let GoMethodContract { lookup, interface } = contract;
        let Some(source_role) = self.go_source_role_for_mount(
            context_id,
            SelectedResolutionMountOrdinal::new(ordinal),
            cancellation,
        )?
        else {
            return Ok(None);
        };
        self.with_go_hierarchy_forward(
            context_id,
            &source_role,
            method,
            cancellation,
            session,
            |forward| {
                forward.go_method_satisfaction(method, lookup, &[interface], |candidate| {
                    self.go_hierarchy_method_identity(context_id, visible_role, candidate)
                })
            },
        )
    }

    fn go_selected_type_satisfaction(
        &self,
        context_id: i64,
        source_role: &str,
        receiver: crate::analyzer::resolution::ResolutionTypeRef,
        interface: SemanticId,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<Option<crate::analyzer::resolution::fact_resolution::go_methods::GoTypeSatisfaction>>
    {
        self.with_go_hierarchy_forward(
            context_id,
            source_role,
            receiver.identity(),
            cancellation,
            session,
            |forward| {
                forward.go_type_satisfaction(receiver, interface, |candidate| {
                    self.go_hierarchy_method_identity(context_id, source_role, candidate)
                })
            },
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn go_selected_type_satisfaction_for_test(
        &self,
        context_id: i64,
        source_role: &str,
        receiver: crate::analyzer::resolution::ResolutionTypeRef,
        interface: SemanticId,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<
        Option<crate::analyzer::resolution::fact_resolution::go_methods::GoMethodSatisfaction>,
    > {
        Ok(self
            .go_selected_type_satisfaction(
                context_id,
                source_role,
                receiver,
                interface,
                cancellation,
                session,
            )?
            .map(|result| result.outcome))
    }

    fn go_satisfying_receivers_for_lookup(
        &self,
        context_id: i64,
        source_role: &str,
        contract: GoMethodContract,
        name: &str,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<(
        GoDirectSubtypeAnswer,
        Vec<crate::analyzer::resolution::ResolutionTypeRef>,
    )> {
        let GoMethodContract { lookup, interface } = contract;
        let mut answer = GoDirectSubtypeAnswer {
            edges: Vec::new(),
            ambiguous: Vec::new(),
            open: Vec::new(),
            open_reasons: Vec::new(),
            read_keys: GoHierarchyReadKeys::default(),
        };
        let mut candidate_owners = Vec::new();
        let typed = self.ready.typed_source();
        match typed.go_lookup_read_keys(
            &[lookup],
            TypedFactRelation::InterfaceMethodLookup,
            cancellation,
        )? {
            Some(keys) => answer.read_keys.names.extend(keys),
            None => {
                answer.open_reasons.push("method lookup key was cancelled");
                return Ok((answer, candidate_owners));
            }
        }
        let mut interface_nominations = Vec::new();
        let mut interface_stopped = false;
        let mut interface_callback =
            |page: &[crate::analyzer::store::resolution_typed::GoLookupCandidate]| {
                if cancellation.is_cancelled() || !session.scope_steps(1) {
                    interface_stopped = true;
                    return Ok(false);
                }
                interface_nominations.extend_from_slice(page);
                Ok(true)
            };
        let interface_outcome = typed.visit_go_interface_method_candidate_pages(
            &[lookup],
            cancellation,
            &mut TypedFactPageVisitor::new(&mut interface_callback),
        )?;
        if interface_stopped || !interface_outcome.is_exhausted() {
            answer
                .open_reasons
                .push("interface method seek cancelled or exhausted its budget");
        }
        let connection = self.ready.inventory.connection();
        for nomination in interface_nominations {
            if cancellation.is_cancelled() || !session.scope_steps(1) {
                answer
                    .open_reasons
                    .push("interface nominee confirmation cancelled or exhausted its budget");
                break;
            }
            let Some(role) =
                self.go_source_role_for_mount(context_id, nomination.mount, cancellation)?
            else {
                answer
                    .open_reasons
                    .push("interface candidate source role is unavailable");
                continue;
            };
            if role != "go" && role != source_role {
                continue;
            }
            let mut statement =
                connection.prepare_cached(GO_METHOD_INTERFACE_OWNERS_SQL.as_str())?;
            let owners = statement
                .query_map(
                    params![
                        nomination.mount.get(),
                        nomination.blob_id,
                        name,
                        context_id,
                        source_role
                    ],
                    |row| row.get::<_, u32>(0),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let unbound = owners.is_empty()
                || connection
                    .prepare_cached(GO_UNPROJECTED_INTERFACE_METHOD_SQL.as_str())?
                    .query_row(params![nomination.blob_id, name], |row| {
                        row.get::<_, bool>(0)
                    })?;
            candidate_owners.extend(owners.into_iter().map(|key| {
                crate::analyzer::resolution::ResolutionTypeRef::new(
                    SemanticId::local(nomination.mount.get(), key),
                    0,
                )
            }));
            if unbound {
                answer
                    .open_reasons
                    .push("interface method has no declaring interface identity");
            }
        }
        let lookups = [DeferredMemberOwnerLookupName::new(lookup)];
        let mut methods = Vec::new();
        let mut stopped = false;
        let mut callback = |page: &[SelectedTypedRow<LoweredDeferredMemberOwner>]| {
            if cancellation.is_cancelled() || !session.scope_steps(1) {
                stopped = true;
                return Ok(false);
            }
            methods.extend(page.iter().filter_map(|row| {
                (row.row().kind() == ResolutionMemberKind::Method).then_some(row.row().definition())
            }));
            Ok(true)
        };
        let outcome = typed.visit_deferred_member_owner_pages_for_lookup_names(
            TypedFactRequest::new(&lookups),
            cancellation,
            &mut TypedFactPageVisitor::new(&mut callback),
        )?;
        if stopped || !outcome.is_exhausted() || cancellation.is_cancelled() {
            answer
                .open_reasons
                .push("method candidate seek cancelled or exhausted its budget");
        }
        methods.sort_unstable();
        methods.dedup();
        for method in methods {
            if cancellation.is_cancelled() || !session.scope_steps(1) {
                answer
                    .open_reasons
                    .push("method confirmation cancelled or exhausted its budget");
                break;
            }
            let Some(ordinal) = method.ordinal() else {
                answer
                    .open_reasons
                    .push("method candidate has no selected mount");
                continue;
            };
            let role = self.go_source_role_for_mount(
                context_id,
                SelectedResolutionMountOrdinal::new(ordinal),
                cancellation,
            )?;
            let Some(role) = role else {
                answer
                    .open_reasons
                    .push("method candidate source role is unavailable");
                continue;
            };
            if role != "go" && role != source_role {
                continue;
            }
            let Some(outcomes) = self.go_candidate_method_satisfaction(
                context_id,
                source_role,
                method,
                GoMethodContract { lookup, interface },
                cancellation,
                session,
            )?
            else {
                answer
                    .open_reasons
                    .push("method satisfaction context is unavailable");
                continue;
            };
            for outcome in outcomes {
                candidate_owners.extend(outcome.candidate_receivers.iter().copied());
                match outcome.outcome {
                    GoMethodSatisfaction::Satisfies => {
                        for receiver in outcome.satisfying_receivers {
                            if receiver.indirection() != 0 {
                                continue;
                            }
                            let identity = receiver.identity();
                            match self.go_type_supports(
                                context_id,
                                source_role,
                                identity,
                                cancellation,
                            )? {
                                GoTypeSupport::Supported => answer.edges.push(identity),
                                GoTypeSupport::Open => answer
                                    .open_reasons
                                    .push("alias endpoint has no selected declaration identity"),
                                GoTypeSupport::Unsupported => answer
                                    .open_reasons
                                    .push("method receiver has no selected declaration identity"),
                            }
                        }
                    }
                    GoMethodSatisfaction::Inconclusive(reason) => answer.open_reasons.push(reason),
                    GoMethodSatisfaction::DoesNotSatisfy => {}
                }
            }
        }
        answer.edges.sort_unstable();
        answer.edges.dedup();
        candidate_owners.sort_unstable();
        candidate_owners.dedup();
        Ok((answer, candidate_owners))
    }

    #[allow(clippy::too_many_arguments)]
    fn go_close_satisfying_embeddings(
        &self,
        context_id: i64,
        source_role: &str,
        interface: SemanticId,
        strict_target: Option<SemanticId>,
        seeds: &[SemanticId],
        receiver_forms: &[u32],
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<GoEmbeddingClosure> {
        // The largest-form rule below holds for a value receiver and one pointer
        // level only; deeper indirections are not legal receiver forms.
        assert!(
            !receiver_forms.is_empty() && receiver_forms.iter().all(|&form| form <= 1),
            "Go receiver forms are a nonempty subset of {{0, 1}}: {receiver_forms:?}"
        );
        let mut completed = std::collections::HashMap::new();
        let mut answer = GoDirectSubtypeAnswer {
            edges: Vec::new(),
            ambiguous: Vec::new(),
            open: Vec::new(),
            open_reasons: Vec::new(),
            read_keys: GoHierarchyReadKeys::default(),
        };
        let mut queue = std::collections::VecDeque::from(seeds.to_vec());
        let mut visited = std::collections::HashSet::<SemanticId>::new();
        while let Some(parent) = queue.pop_front() {
            if !visited.insert(parent) {
                continue;
            }
            if cancellation.is_cancelled() || !session.scope_steps(1) {
                answer
                    .open_reasons
                    .push("embedding closure cancelled or exhausted its budget");
                break;
            }
            if Some(parent) != strict_target {
                // Which receiver forms need a proof depends on the parent's proven
                // declaration category (https://go.dev/ref/spec#Method_sets). For a
                // struct S, the method set of *S contains S's with the same
                // selections, so only the largest requested form is proven. A
                // pointer to an interface has no methods, so an interface is proven
                // as itself. Any other or unknown category keeps every requested form.
                let kind = if receiver_forms.iter().any(|&form| form != 0) {
                    self.ready
                        .typed_source()
                        .go_member_declarations(&[parent], cancellation)?
                        .and_then(|declarations| {
                            declarations
                                .into_iter()
                                .find(|declaration| declaration.definition == parent)
                                .map(|declaration| declaration.kind)
                        })
                } else {
                    None
                };
                let forms = match &kind {
                    Some(crate::analyzer::resolution::GoMemberDeclarationKind::Struct {
                        ..
                    }) => receiver_forms.iter().copied().max().into_iter().collect(),
                    Some(crate::analyzer::resolution::GoMemberDeclarationKind::Interface {
                        ..
                    }) => receiver_forms
                        .iter()
                        .copied()
                        .filter(|&form| form == 0)
                        .collect(),
                    _ => receiver_forms.to_vec(),
                };
                let mut satisfied = false;
                for form in forms {
                    // Each proof charges its own work to the session; this only
                    // observes a stop between the forms of one parent. The bounded
                    // session's own token can stop it while the outer token is clear.
                    if cancellation.is_cancelled() || !session.observe_cancellation() {
                        answer.open.push(parent);
                        answer
                            .open_reasons
                            .push("embedding proof was cancelled or exhausted its budget");
                        break;
                    }
                    if form != 0 && kind.is_none() {
                        answer.open.push(parent);
                        answer
                            .open_reasons
                            .push("embedded candidate declaration kind is unavailable");
                        continue;
                    }
                    let receiver =
                        crate::analyzer::resolution::ResolutionTypeRef::new(parent, form);
                    match self.go_selected_type_satisfaction(
                        context_id,
                        source_role,
                        receiver,
                        interface,
                        cancellation,
                        session,
                    )? {
                        Some(result) if result.outcome == GoMethodSatisfaction::Satisfies => {
                            satisfied = true;
                            completed.insert(receiver, result);
                        }
                        Some(result) if result.outcome == GoMethodSatisfaction::DoesNotSatisfy => {}
                        Some(result) => {
                            answer.open.push(parent);
                            if let GoMethodSatisfaction::Inconclusive(reason) = result.outcome {
                                answer.open_reasons.push(reason);
                            }
                        }
                        None => {
                            answer.open.push(parent);
                            answer
                                .open_reasons
                                .push("embedded candidate satisfaction context is unavailable");
                        }
                    }
                }
                if satisfied {
                    answer.edges.push(parent);
                }
            }
            let descendants =
                self.go_embedding_subtypes(context_id, source_role, parent, cancellation, session)?;
            answer.read_keys.names.extend(descendants.read_keys.names);
            answer.read_keys.coverage = descendants.read_keys.coverage;
            answer.open.extend(descendants.open);
            answer.open.extend(descendants.ambiguous);
            answer.open_reasons.extend(descendants.open_reasons);
            for child in descendants.edges {
                queue.push_back(child);
            }
        }
        answer.edges.sort_unstable();
        answer.edges.dedup();
        answer.open.sort_unstable();
        answer.open.dedup();
        Ok(GoEmbeddingClosure { answer, completed })
    }

    /// Confirm inverse embedding nominations with the forward proof.
    fn go_embedding_subtypes(
        &self,
        context_id: i64,
        source_role: &str,
        target: SemanticId,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<GoDirectSubtypeAnswer> {
        let mut answer = GoDirectSubtypeAnswer {
            edges: Vec::new(),
            ambiguous: Vec::new(),
            open: Vec::new(),
            open_reasons: Vec::new(),
            read_keys: GoHierarchyReadKeys::default(),
        };
        answer.read_keys.coverage = Some(GoHierarchyCoverageReadKey {
            context_id,
            selection_fingerprint: self.ready.inventory.fingerprint(),
        });
        if let Some(reason) = self
            .go_hierarchy_selection_coverage(context_id, source_role)?
            .incomplete_reason()
        {
            answer.open_reasons.push(reason);
        }
        let Some(name) = self.go_point_type_name(target, cancellation)? else {
            answer
                .open_reasons
                .push("interface method has no declaring interface identity");
            return Ok(answer);
        };
        if self.go_type_supports(context_id, source_role, target, cancellation)?
            != GoTypeSupport::Supported
        {
            answer
                .open_reasons
                .push("target has no selected declaration identity");
            return Ok(answer);
        }
        let typed = self.ready.typed_source();
        let connection = self.ready.inventory.connection();
        let mut names = vec![name];
        let mut inspected = std::collections::HashSet::new();
        let mut next_name = 0;
        while next_name < names.len() {
            if names.len() > 64 || cancellation.is_cancelled() || !session.scope_steps(1) {
                answer
                    .open_reasons
                    .push("alias inverse closure exceeded its budget");
                break;
            }
            let sought = names[next_name].clone();
            next_name += 1;
            let lookup = crate::analyzer::resolution::ResolutionLookupSemanticRecipe::new(
                Language::Go,
                ResolutionNamespace::Type,
                &sought,
            )
            .semantic(&self.ready.shared_names());
            match typed.go_lookup_read_keys(
                &[lookup],
                TypedFactRelation::AliasTargetLookup,
                cancellation,
            )? {
                Some(keys) => answer.read_keys.names.extend(keys),
                None => {
                    answer
                        .open_reasons
                        .push("alias target lookup key was cancelled");
                    break;
                }
            }
            let mut candidates = Vec::new();
            let mut stopped = false;
            let mut callback =
                |page: &[crate::analyzer::store::resolution_typed::GoLookupCandidate]| {
                    if cancellation.is_cancelled() || !session.scope_steps(1) {
                        stopped = true;
                        return Ok(false);
                    }
                    candidates.extend_from_slice(page);
                    Ok(true)
                };
            let outcome = typed.visit_go_alias_target_candidate_pages(
                &[lookup],
                cancellation,
                &mut TypedFactPageVisitor::new(&mut callback),
            )?;
            if stopped || !outcome.is_exhausted() {
                answer
                    .open_reasons
                    .push("alias target seek cancelled or exhausted its budget");
                break;
            }
            for candidate in candidates {
                if cancellation.is_cancelled() || !session.scope_steps(1) {
                    answer
                        .open_reasons
                        .push("alias confirmation cancelled or exhausted its budget");
                    break;
                }
                let Some(role) =
                    self.go_source_role_for_mount(context_id, candidate.mount, cancellation)?
                else {
                    answer
                        .open_reasons
                        .push("alias candidate source role is unavailable");
                    continue;
                };
                if role != "go" && role != source_role {
                    continue;
                }
                let mut statement =
                    connection.prepare_cached(GO_INVERSE_ALIAS_NOMINEES_SQL.as_str())?;
                let aliases = statement
                    .query_map(params![candidate.blob_id, &sought], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                drop(statement);
                for (declaration_id, alias_name, type_id) in aliases {
                    if !inspected.insert((candidate.mount, declaration_id)) {
                        continue;
                    }
                    let mut statement =
                        connection.prepare_cached(GO_EMBEDDED_REFERENCE_SQL.as_str())?;
                    let sites = statement
                        .query_map(params![candidate.blob_id, type_id], |row| {
                            row.get::<_, u32>(0)
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    drop(statement);
                    let [site] = sites.as_slice() else {
                        answer
                            .open_reasons
                            .push("alias nominee has no unique selected native reference");
                        continue;
                    };
                    let reference = SemanticId::local(candidate.mount.get(), *site);
                    match self.go_alias_chain_terminal(
                        context_id,
                        source_role,
                        reference,
                        cancellation,
                        session,
                    )? {
                        Ok(GoAliasTerminal::Selected(terminal)) if terminal == target => {
                            if !names.contains(&alias_name) {
                                names.push(alias_name);
                            }
                        }
                        Ok(GoAliasTerminal::Selected(_)) => {}
                        Ok(GoAliasTerminal::Primitive) => answer
                            .open_reasons
                            .push("alias target is outside the mounted workspace"),
                        Err(reason) => answer.open_reasons.push(reason),
                    }
                }
            }
        }
        let lookups = names
            .iter()
            .map(|name| {
                crate::analyzer::resolution::ResolutionLookupSemanticRecipe::new(
                    Language::Go,
                    ResolutionNamespace::Type,
                    name,
                )
                .semantic(&self.ready.shared_names())
            })
            .collect::<Vec<_>>();
        let mut names_by_identity = std::collections::HashMap::new();
        match typed.go_lookup_read_keys(
            &lookups,
            TypedFactRelation::EmbeddedTypeLookup,
            cancellation,
        )? {
            Some(keys) => {
                for (name, key) in names.iter().zip(&keys) {
                    if let Some(identity_id) = key.identity_id {
                        names_by_identity.insert(identity_id, name.as_str());
                    }
                }
                answer.read_keys.names.extend(keys);
            }
            None => {
                answer
                    .open_reasons
                    .push("embedding lookup key was cancelled");
                return Ok(answer);
            }
        }
        let mut candidates = Vec::new();
        let mut stopped = false;
        let mut callback =
            |page: &[crate::analyzer::store::resolution_typed::GoLookupCandidate]| {
                if cancellation.is_cancelled() || !session.scope_steps(1) {
                    stopped = true;
                    return Ok(false);
                }
                candidates.extend_from_slice(page);
                Ok(true)
            };
        let outcome = typed.visit_go_embedded_type_candidate_pages(
            &lookups,
            cancellation,
            &mut TypedFactPageVisitor::new(&mut callback),
        )?;
        if stopped || !outcome.is_exhausted() || cancellation.is_cancelled() {
            answer
                .open_reasons
                .push("hierarchy seek cancelled or exhausted its budget");
        }
        for candidate in candidates {
            if cancellation.is_cancelled() || !session.scope_steps(1) {
                answer
                    .open_reasons
                    .push("hierarchy confirmation cancelled or exhausted its budget");
                break;
            }
            let role = self.go_source_role_for_mount(context_id, candidate.mount, cancellation)?;
            let Some(role) = role else {
                answer
                    .open_reasons
                    .push("candidate source role is unavailable");
                continue;
            };
            if role != "go" && role != source_role {
                continue;
            }
            let Some(spelled) = names_by_identity.get(&candidate.identity_id) else {
                answer
                    .open_reasons
                    .push("embedded nomination has no selected lookup name");
                continue;
            };
            let mut statement =
                connection.prepare_cached(GO_INVERSE_EMBEDDING_OWNERS_SQL.as_str())?;
            let owners = statement
                .query_map(params![candidate.blob_id, spelled], |row| {
                    row.get::<_, u32>(0)
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(statement);
            for key in owners {
                if cancellation.is_cancelled() || !session.scope_steps(1) {
                    answer
                        .open_reasons
                        .push("hierarchy confirmation cancelled or exhausted its budget");
                    break;
                }
                let owner = SemanticId::local(candidate.mount.get(), key);
                let forward = self.go_direct_embeddings(
                    context_id,
                    source_role,
                    owner,
                    cancellation,
                    session,
                )?;
                // The inverse query enumerates structural satisfaction itself;
                // only an embedding gap makes this confirmation incomplete.
                if !forward.embeddings_complete() {
                    answer.open.push(owner);
                }
                for parent in &forward.parents {
                    if parent.targets.contains(&target) {
                        if parent.targets.len() == 1 && parent.open_reason.is_none() {
                            answer.edges.push(owner);
                        } else {
                            answer.ambiguous.push(owner);
                        }
                    }
                }
            }
        }
        answer.edges.sort_unstable();
        answer.edges.dedup();
        answer.ambiguous.sort_unstable();
        answer.ambiguous.dedup();
        answer.open.sort_unstable();
        answer.open.dedup();
        Ok(answer)
    }

    /// Direct embedded descendants and interface implementers in the selected Go context.
    /// A structural subtype edge requires the value type (form 0) to satisfy
    /// the interface. Pointer-inclusive matching belongs to method families.
    pub fn go_direct_subtypes(
        &self,
        context_id: i64,
        source_role: &str,
        target: SemanticId,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<GoDirectSubtypeAnswer> {
        let mut answer =
            self.go_embedding_subtypes(context_id, source_role, target, cancellation, session)?;
        let typed = self.ready.typed_source();
        let connection = self.ready.inventory.connection();
        match typed.go_member_declarations(&[target], cancellation)? {
            Some(declarations) => {
                if declarations.iter().any(|declaration| {
                    matches!(
                        declaration.kind,
                        crate::analyzer::resolution::GoMemberDeclarationKind::Interface { .. }
                    )
                }) {
                    match self.go_interface_method_inventory(
                        context_id,
                        source_role,
                        target,
                        cancellation,
                        session,
                    )? {
                        Some(methods) if !methods.complete => answer
                            .open_reasons
                            .push("interface method set is incomplete"),
                        Some(methods) if methods.methods.is_empty() => answer
                            .open_reasons
                            .push("empty interface method set is unenumerable"),
                        Some(methods) => {
                            let mut names = methods
                                .methods
                                .iter()
                                .map(|method| method.callable_lookup)
                                .collect::<Vec<_>>();
                            names.sort_unstable();
                            names.dedup();
                            let Some(keys) = typed.go_lookup_read_keys(
                                &names,
                                TypedFactRelation::InterfaceMethodLookup,
                                cancellation,
                            )?
                            else {
                                answer
                                    .open_reasons
                                    .push("method lookup keys were cancelled");
                                return Ok(answer);
                            };
                            answer.read_keys.names.extend(keys.iter().copied());
                            let mut rarest = None;
                            for key in keys {
                                if cancellation.is_cancelled() || !session.scope_steps(1) {
                                    answer.open_reasons.push(
                                        "method name count cancelled or exhausted its budget",
                                    );
                                    break;
                                }
                                let count: i64 = match key.identity_id {
                                    Some(identity) => connection
                                        .prepare_cached(GO_METHOD_LOOKUP_COUNT_SQL)?
                                        .query_row([identity], |row| row.get(0))?,
                                    None => 0,
                                };
                                let candidate = (count, key.name);
                                if rarest.is_none_or(|current| candidate < current) {
                                    rarest = Some(candidate);
                                }
                            }
                            if let Some((_, lookup)) = rarest {
                                let Some(definition) = methods
                                    .methods
                                    .iter()
                                    .find(|method| method.callable_lookup == lookup)
                                    .and_then(|method| method.definition)
                                else {
                                    answer
                                        .open_reasons
                                        .push("interface method has no selected Go name");
                                    return Ok(answer);
                                };
                                let Some((name, _)) = self.go_hierarchy_method_identity(
                                    context_id,
                                    source_role,
                                    definition,
                                )?
                                else {
                                    answer
                                        .open_reasons
                                        .push("interface method has no selected Go name");
                                    return Ok(answer);
                                };
                                let (satisfaction, candidate_owners) = self
                                    .go_satisfying_receivers_for_lookup(
                                        context_id,
                                        source_role,
                                        GoMethodContract {
                                            lookup,
                                            interface: target,
                                        },
                                        &name,
                                        cancellation,
                                        session,
                                    )?;
                                let closure = self.go_close_satisfying_embeddings(
                                    context_id,
                                    source_role,
                                    target,
                                    Some(target),
                                    &candidate_owners
                                        .iter()
                                        .filter(|receiver| receiver.indirection() == 0)
                                        .map(|receiver| receiver.identity())
                                        .collect::<Vec<_>>(),
                                    &[0],
                                    cancellation,
                                    session,
                                )?;
                                let closure = closure.answer;
                                answer.edges.extend(satisfaction.edges);
                                answer.edges.extend(closure.edges);
                                answer.ambiguous.extend(satisfaction.ambiguous);
                                answer.ambiguous.extend(closure.ambiguous);
                                answer.open.extend(satisfaction.open);
                                answer.open.extend(closure.open);
                                answer.open_reasons.extend(satisfaction.open_reasons);
                                answer.open_reasons.extend(closure.open_reasons);
                                answer.read_keys.names.extend(satisfaction.read_keys.names);
                                answer.read_keys.names.extend(closure.read_keys.names);
                            }
                        }
                        None => answer
                            .open_reasons
                            .push("interface method set is unavailable"),
                    }
                }
            }
            None => answer
                .open_reasons
                .push("interface membership read was cancelled"),
        }
        // Direct subtypes are strict, even when an embedding points back to its target.
        answer.edges.retain(|candidate| *candidate != target);
        answer.ambiguous.retain(|candidate| *candidate != target);
        answer.open.retain(|candidate| *candidate != target);
        answer.edges.sort_unstable();
        answer.edges.dedup();
        answer.ambiguous.sort_unstable();
        answer.ambiguous.dedup();
        answer.open.sort_unstable();
        answer.open.dedup();
        Ok(answer)
    }

    /// Resolve a selected Go type reference using the same forward operation
    /// that confirms direct embeddings.
    fn go_hierarchy_reference_binding(
        &self,
        context_id: i64,
        source_role: &str,
        reference: SemanticId,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<Option<(Vec<SemanticId>, ResolutionCompletion, bool)>> {
        let Some(ordinal) = reference.ordinal() else {
            return Ok(None);
        };
        let mount = self
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let path = mount.persisted_relative_path();
        let prepared = match self.go_file_import_context_with_role(
            context_id,
            path,
            source_role,
            cancellation,
        )? {
            GoPreparedImportContextOutcome::Ready(prepared) => *prepared,
            GoPreparedImportContextOutcome::Cancelled
            | GoPreparedImportContextOutcome::Unavailable => return Ok(None),
        };
        let context = match self.prepare_context(
            prepared.context,
            cancellation,
            &SelectedResolutionContextMetrics,
        )? {
            SelectedResolutionContextValidationOutcome::Ready(context) => context,
            SelectedResolutionContextValidationOutcome::Cancelled => return Ok(None),
        };
        if cancellation.is_cancelled() || !session.observe_cancellation() {
            return Ok(None);
        }
        let Some(blueprint) = self.ready.publish_prepared_context(
            context,
            cancellation,
            session,
            Some(&self.jvm_context_blueprints),
            |blueprint| {
                if cancellation.is_cancelled() || !session.observe_cancellation() {
                    return Ok(ContextRegistrationOutcome::Cancelled);
                }
                self.ready.register_context(blueprint, cancellation)
            },
        )?
        else {
            return Ok(None);
        };
        if cancellation.is_cancelled() || !session.observe_cancellation() {
            return Ok(None);
        }
        let lexical = self.ready.lexical_source();
        let typed = self.ready.typed_source();
        let lexical = SeamProfiled::observing(&lexical);
        let typed = SeamProfiled::observing(&typed);
        self.with_go_forward_operation(
            GoForwardOperationContext {
                blueprint: &blueprint,
                demand: prepared.demand,
                caller_path: path,
                lexical: &lexical,
                typed: &typed,
                cancellation,
                session,
            },
            None,
            |forward| {
                if cancellation.is_cancelled() || !session.scope_steps(1) {
                    return Ok(None);
                }
                let result = forward.resolve_reference_with_metrics(
                    reference,
                    &mut ResolutionBatchMetrics::default(),
                )?;
                let binding = result.binding();
                let targets = binding.targets();
                let primitive = if let [target] = targets {
                    if self.go_type_supports(context_id, source_role, *target, cancellation)?
                        == GoTypeSupport::Unsupported
                    {
                        let Some(descriptors) =
                            forward.read_intrinsic_type_descriptors(&[*target])?
                        else {
                            return Ok(None);
                        };
                        matches!(descriptors.as_ref(), [descriptor]
                            if descriptor.identity() == *target
                                && descriptor.kind() == IntrinsicTypeKind::Primitive)
                    } else {
                        false
                    }
                } else {
                    false
                };
                Ok(Some((
                    targets.to_vec(),
                    binding.completion().clone(),
                    primitive,
                )))
            },
        )
    }

    /// Follow a selected reference through aliases to a selected declaration
    /// or an exactly typed primitive terminal.
    fn go_alias_chain_terminal(
        &self,
        context_id: i64,
        source_role: &str,
        mut reference: SemanticId,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<std::result::Result<GoAliasTerminal, &'static str>> {
        let mut visited = std::collections::HashSet::new();
        for _ in 0..32 {
            if cancellation.is_cancelled() || !session.scope_steps(1) {
                return Ok(Err("alias chain cancelled or exhausted its budget"));
            }
            let Some((targets, completion, primitive)) = self.go_hierarchy_reference_binding(
                context_id,
                source_role,
                reference,
                cancellation,
                session,
            )?
            else {
                return Ok(Err("alias target forward context is unavailable"));
            };
            if completion != ResolutionCompletion::Complete || targets.is_empty() {
                return Ok(Err("alias target is unresolved"));
            }
            let [target] = targets.as_slice() else {
                return Ok(Err("alias target binding is ambiguous"));
            };
            if !visited.insert(*target) {
                return Ok(Err("alias target cycle"));
            }
            match self.go_type_supports(context_id, source_role, *target, cancellation)? {
                GoTypeSupport::Supported => return Ok(Ok(GoAliasTerminal::Selected(*target))),
                GoTypeSupport::Unsupported => {
                    if primitive {
                        return Ok(Ok(GoAliasTerminal::Primitive));
                    }
                    return Ok(Err("alias target is outside the mounted workspace"));
                }
                GoTypeSupport::Open => {}
            }
            let (Some(mount), Some(key)) = (target.ordinal(), target.local_key()) else {
                return Ok(Err("alias target has no selected declaration"));
            };
            let connection = self.ready.inventory.connection();
            let alias: Option<(i64, Option<i64>)> = connection
                .prepare_cached(GO_ALIAS_TARGET_TYPE_SQL.as_str())?
                .query_row(params![mount, key, context_id, source_role], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .optional()?;
            let Some((blob_id, Some(type_id))) = alias else {
                return Ok(Err("alias target has no selected declaration identity"));
            };
            let mut statement = connection.prepare_cached(GO_EMBEDDED_REFERENCE_SQL.as_str())?;
            let sites = statement
                .query_map(params![blob_id, type_id], |row| row.get::<_, u32>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let [site] = sites.as_slice() else {
                return Ok(Err("alias target has no unique selected native reference"));
            };
            reference = SemanticId::local(mount, *site);
        }
        Ok(Err("alias chain exceeded its bound"))
    }

    /// Scan once for a walk/context/role; callers retain this value and the
    /// read receipt captured around the call for other roots in that walk.
    pub fn go_forward_empty_interface_scan(
        &self,
        context_id: i64,
        source_role: &str,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<GoForwardEmptyInterfaceScan> {
        let mut scan = GoForwardEmptyInterfaceScan {
            context_id,
            source_role: source_role.to_owned(),
            empty: Vec::new(),
            open_reasons: Vec::new(),
            complete: true,
        };
        if let Some(reason) =
            self.go_forward_package_census(context_id, source_role, None, cancellation, session)?
        {
            scan.open_reasons.push(reason);
            scan.complete = false;
        }
        let connection = self.ready.inventory.connection();
        let mut statement = connection.prepare_cached(GO_SELECTED_INTERFACES_SQL.as_str())?;
        let mut rows = statement.query(params![context_id, source_role])?;
        let mut declared = Vec::new();
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() || !session.scope_steps(1) {
                scan.open_reasons
                    .push("forward empty interface scan was stopped");
                scan.complete = false;
                break;
            }
            declared.push((
                SemanticId::local(row.get::<_, u32>(0)?, row.get::<_, u32>(1)?),
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, bool>(3)?,
            ));
        }
        drop(rows);
        drop(statement);
        for (interface, has_named_children, has_own_method) in declared {
            if cancellation.is_cancelled() || !session.observe_cancellation() {
                scan.open_reasons
                    .push("forward empty interface scan was stopped");
                scan.complete = false;
                break;
            }
            // A declared method excludes an empty interface, but supplies no
            // completeness proof for its method set. Only the producer's
            // exact kind-13 syntax flag proves an otherwise methodless body
            // empty; absent or malformed type evidence still needs inventory.
            if has_own_method {
                continue;
            }
            if has_named_children == Some(0) {
                scan.empty.push(interface);
                continue;
            }
            match self.go_interface_method_inventory(
                context_id,
                source_role,
                interface,
                cancellation,
                session,
            )? {
                Some(inventory) if inventory.complete && inventory.methods.is_empty() => {
                    scan.empty.push(interface);
                }
                Some(inventory) if !inventory.complete => {
                    scan.open_reasons
                        .push("forward interface inventory is incomplete");
                    scan.complete = false;
                }
                None => {
                    scan.open_reasons
                        .push("forward interface inventory is unavailable");
                    scan.complete = false;
                }
                _ => {}
            }
        }
        let mut aliases = connection.prepare_cached(GO_SELECTED_ALIASES_SQL.as_str())?;
        let mut alias_rows = aliases.query(params![context_id, source_role])?;
        let mut selected_aliases = Vec::new();
        while let Some(row) = alias_rows.next()? {
            if cancellation.is_cancelled() || !session.scope_steps(1) {
                scan.open_reasons
                    .push("forward inline interface alias scan was stopped");
                scan.complete = false;
                break;
            }
            selected_aliases.push((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, u32>(2)?,
            ));
        }
        drop(alias_rows);
        drop(aliases);
        for (blob_id, target_type_id, mount) in selected_aliases {
            if cancellation.is_cancelled() || !session.observe_cancellation() {
                scan.open_reasons
                    .push("forward inline interface alias scan was stopped");
                scan.complete = false;
                break;
            }
            let Some(target_type_id) = target_type_id else {
                scan.open_reasons
                    .push("forward inline interface alias target is unavailable");
                scan.complete = false;
                continue;
            };
            let (inline_interface, named, capped, unsupported): (bool, bool, bool, bool) =
                connection
                    .prepare_cached(GO_ALIAS_INTERFACE_HEAD_SQL.as_str())?
                    .query_row(params![blob_id, target_type_id], |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                    })?;
            if cancellation.is_cancelled() || !session.scope_steps(1) {
                scan.open_reasons
                    .push("forward inline interface alias scan was stopped");
                scan.complete = false;
                break;
            }
            if inline_interface {
                scan.open_reasons
                    .push("forward inline interface alias inventory is unavailable");
                scan.complete = false;
            }
            if capped {
                scan.open_reasons
                    .push("forward inline interface alias head exceeded bounded traversal");
                scan.complete = false;
            }
            if unsupported {
                scan.open_reasons
                    .push("forward inline interface alias head is unsupported or missing");
                scan.complete = false;
            }
            if named && !inline_interface && !capped && !unsupported {
                let mut sites = connection.prepare_cached(GO_EMBEDDED_REFERENCE_SQL.as_str())?;
                let references = sites
                    .query_map(params![blob_id, target_type_id], |row| row.get::<_, u32>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                let terminal = match references.as_slice() {
                    [site] => self.go_alias_chain_terminal(
                        context_id,
                        source_role,
                        SemanticId::local(mount, *site),
                        cancellation,
                        session,
                    )?,
                    _ => Err("alias target has no unique selected native reference"),
                };
                if terminal.is_err() {
                    scan.open_reasons
                        .push("alias target has no complete selected terminal");
                    scan.complete = false;
                }
                if cancellation.is_cancelled() || !session.observe_cancellation() {
                    scan.open_reasons
                        .push("forward inline interface alias scan was stopped");
                    scan.complete = false;
                    break;
                }
            }
        }
        Ok(scan)
    }

    /// Prove that every expected peer in the selected package universe has a
    /// unique mounted, ready, recovery-free Go publication. A caller may pass
    /// one exact package or ask for the whole selected context universe.
    /// `None` means certified; `Some` is explicit incomplete evidence.
    pub fn go_forward_package_census(
        &self,
        context_id: i64,
        source_role: &str,
        package_id: Option<i64>,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<Option<&'static str>> {
        if cancellation.is_cancelled() || !session.scope_steps(1) {
            return Ok(Some("forward census was stopped"));
        }
        if self.go_hierarchy_selection_coverage(context_id, source_role)?
            != super::go_context::GoHierarchySelectionCoverage::Workspace
        {
            return Ok(Some("forward census scope is incomplete"));
        }
        let connection = self.ready.inventory.connection();
        if cancellation.is_cancelled() || !session.scope_steps(1) {
            return Ok(Some("forward census was stopped"));
        }
        let unplaced: bool = connection
            .prepare_cached(&format!(
                "SELECT EXISTS(SELECT 1 FROM ({}) LIMIT 1)",
                super::go_context::UNPLACED_TRANSIENT_SOURCES
            ))?
            .query_row([], |row| row.get(0))?;
        if !session.scope_steps(1) || cancellation.is_cancelled() {
            return Ok(Some("forward census was stopped"));
        }
        if unplaced {
            return Ok(Some("forward census has unplaced transient source"));
        }
        let mut statement = connection.prepare_cached(GO_FORWARD_CENSUS_SQL.as_str())?;
        let mut rows = statement.query(params![context_id, source_role, package_id])?;
        let mut seen = std::collections::HashSet::new();
        let mut any = false;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() || !session.scope_steps(1) {
                return Ok(Some("forward census was stopped"));
            }
            any = true;
            let package: i64 = row.get(0)?;
            let accepted: bool = row.get(1)?;
            let version: Option<i64> = row.get(2)?;
            let ordinal: Option<u32> = row.get(3)?;
            let blob_id: Option<i64> = row.get(4)?;
            let oid: Option<String> = row.get(5)?;
            let generation: Option<i64> = row.get(6)?;
            let scoped: Option<u32> = row.get(7)?;
            let Some(version) = version else {
                return Ok(Some("forward census package has no selected source"));
            };
            if !accepted
                || !seen.insert((package, version))
                || ordinal.is_none()
                || scoped != ordinal
            {
                return Ok(Some("forward census placement is incomplete or ambiguous"));
            }
            let (Some(blob_id), Some(oid), Some(generation)) = (blob_id, oid, generation) else {
                return Ok(Some("forward census selected content is unavailable"));
            };
            let admitted: Option<i64> = connection
                .prepare_cached(brokk_bifrost_core::analyzer::go_facts::GO_SOURCE_HEADER_SQL)?
                .query_row(
                    params![
                        oid,
                        generation,
                        brokk_bifrost_core::analyzer::go_facts::GO_SOURCE_FACTS_VERSION,
                        crate::analyzer::store::source_facts::SOURCE_FACTS_VERSION
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            if !session.scope_steps(1) || cancellation.is_cancelled() {
                return Ok(Some("forward census was stopped"));
            }
            if admitted != Some(blob_id) {
                return Ok(Some("forward census Go source is not ready"));
            }
            let recovered: bool = connection.prepare_cached("SELECT EXISTS(SELECT 1 FROM main.source_structural_recovered_regions WHERE blob_id=?1)")?.query_row(
                [blob_id], |row| row.get(0),
            )?;
            if !session.scope_steps(1) || cancellation.is_cancelled() {
                return Ok(Some("forward census was stopped"));
            }
            if recovered {
                return Ok(Some("forward census source has recovered regions"));
            }
        }
        if !any {
            return Ok(Some("forward census has no selected source"));
        }
        if cancellation.is_cancelled() || !session.observe_cancellation() {
            return Ok(Some("forward census was stopped"));
        }
        Ok(None)
    }

    /// Resolve embedded and structural parents of a value type (form 0).
    /// A structural parent requires the value type itself to satisfy the
    /// interface. Pointer-inclusive matching belongs to method families.
    /// A source row without a native reference remains explicit open evidence.
    pub fn go_direct_supertypes(
        &self,
        context_id: i64,
        source_role: &str,
        definition: SemanticId,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<GoDirectSupertypeAnswer> {
        let scan =
            self.go_forward_empty_interface_scan(context_id, source_role, cancellation, session)?;
        self.go_direct_supertypes_with_scan(
            context_id,
            source_role,
            definition,
            &scan,
            cancellation,
            session,
        )
    }

    /// The selected scan belongs to this walk, context, and role. The caller
    /// replays its receipt and polls the same session before reusing it.
    pub fn go_direct_supertypes_with_scan(
        &self,
        context_id: i64,
        source_role: &str,
        definition: SemanticId,
        scan: &GoForwardEmptyInterfaceScan,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<GoDirectSupertypeAnswer> {
        assert_eq!(scan.context_id, context_id);
        assert_eq!(scan.source_role, source_role);
        let mut answer =
            self.go_direct_embeddings(context_id, source_role, definition, cancellation, session)?;
        #[cfg(any(test, feature = "test-support"))]
        if answer.embeddings_complete() {
            forward_proof_stop_probe::fire_after_complete_embeddings(session);
        }
        let mut forward_open_reasons = Vec::new();
        if self.go_type_supports(context_id, source_role, definition, cancellation)?
            != GoTypeSupport::Supported
        {
            answer
                .forward_open_reasons
                .push("forward root has no selected declaration identity");
            return Ok(answer);
        }
        let typed = self.ready.typed_source();
        let Some(_) = typed
            .go_member_declarations(&[definition], cancellation)?
            .and_then(|declarations| {
                declarations
                    .into_iter()
                    .find(|declaration| declaration.definition == definition)
                    .map(|declaration| declaration.kind)
            })
        else {
            answer
                .forward_open_reasons
                .push("forward root kind is unavailable");
            return Ok(answer);
        };
        let connection = self.ready.inventory.connection();
        forward_open_reasons.extend(scan.open_reasons.iter().copied());
        let mut names = Vec::new();
        let mut owners = std::collections::VecDeque::from([definition]);
        let mut visited = std::collections::HashSet::new();
        let mut complete = answer.embeddings_complete() && scan.complete;
        while let Some(owner) = owners.pop_front() {
            if !visited.insert(owner) {
                continue;
            }
            if cancellation.is_cancelled() || !session.scope_steps(1) {
                forward_open_reasons.push("forward method inventory was stopped");
                complete = false;
                break;
            }
            let Some(declarations) = typed.go_member_declarations(&[owner], cancellation)? else {
                forward_open_reasons.push("forward owner kind is unavailable");
                complete = false;
                continue;
            };
            let Some(kind) = declarations
                .into_iter()
                .find(|d| d.definition == owner)
                .map(|d| d.kind)
            else {
                forward_open_reasons.push("forward owner kind is unavailable");
                complete = false;
                continue;
            };
            if matches!(
                kind,
                crate::analyzer::resolution::GoMemberDeclarationKind::Interface { .. }
            ) {
                match self.go_interface_method_inventory(
                    context_id,
                    source_role,
                    owner,
                    cancellation,
                    session,
                )? {
                    Some(inventory) => {
                        if !inventory.complete {
                            forward_open_reasons
                                .push("forward interface method inventory is incomplete");
                            complete = false;
                        }
                        names.extend(
                            inventory
                                .methods
                                .into_iter()
                                .map(|method| method.callable_lookup),
                        );
                    }
                    None => {
                        forward_open_reasons
                            .push("forward interface method inventory is unavailable");
                        complete = false;
                    }
                }
            } else {
                let (Some(ordinal), Some(key)) = (owner.ordinal(), owner.local_key()) else {
                    forward_open_reasons.push("forward owner has no local identity");
                    complete = false;
                    continue;
                };
                let mut statement =
                    connection.prepare_cached(GO_OWNER_METHOD_NAMES_SQL.as_str())?;
                let mut rows = statement.query(params![ordinal, key, context_id, source_role])?;
                while let Some(row) = rows.next()? {
                    if cancellation.is_cancelled() || !session.scope_steps(1) {
                        forward_open_reasons.push("forward method inventory was stopped");
                        complete = false;
                        break;
                    }
                    let name: String = row.get(0)?;
                    names.push(self.go_static_member_lookup(&name));
                }
            }
            let embedded = if owner == definition {
                // The first embedding read was already performed above.
                None
            } else {
                Some(self.go_direct_embeddings(
                    context_id,
                    source_role,
                    owner,
                    cancellation,
                    session,
                )?)
            };
            let parents = embedded
                .as_ref()
                .map_or(answer.parents.as_slice(), |a| a.parents.as_slice());
            if embedded.as_ref().is_some_and(|a| !a.embeddings_complete()) {
                forward_open_reasons.push("forward embedding closure is incomplete");
                complete = false;
            }
            for parent in parents {
                if parent.open_reason.is_some()
                    || parent.completion != ResolutionCompletion::Complete
                    || parent.targets.len() != 1
                {
                    forward_open_reasons.push("forward embedded owner is unresolved");
                    complete = false;
                }
                owners.extend(parent.targets.iter().copied());
            }
        }
        names.sort_unstable();
        names.dedup();
        let mut candidates = std::collections::HashSet::new();
        if !names.is_empty() {
            let Some(keys) = typed.go_lookup_read_keys(
                &names,
                TypedFactRelation::InterfaceMethodLookup,
                cancellation,
            )?
            else {
                forward_open_reasons.push("forward method lookup keys were stopped");
                answer.forward_open_reasons = forward_open_reasons;
                return Ok(answer);
            };
            let mut names_by_identity = std::collections::HashMap::new();
            for key in &keys {
                if let Some(identity_id) = key.identity_id {
                    if cancellation.is_cancelled() || !session.scope_steps(1) {
                        forward_open_reasons.push("forward lookup names were stopped");
                        complete = false;
                        break;
                    }
                    let spelling: String = connection
                        .prepare_cached(
                            "SELECT spelling FROM main.resolution_identities WHERE id=?1",
                        )?
                        .query_row([identity_id], |row| row.get(0))?;
                    names_by_identity.insert(identity_id, spelling);
                }
            }
            let mut nominations = Vec::new();
            let mut stopped = false;
            let mut callback =
                |page: &[crate::analyzer::store::resolution_typed::GoLookupCandidate]| {
                    for candidate in page {
                        if cancellation.is_cancelled() || !session.scope_steps(1) {
                            stopped = true;
                            return Ok(false);
                        }
                        nominations.push(*candidate);
                    }
                    Ok(true)
                };
            let outcome = typed.visit_go_interface_method_candidate_pages(
                &names,
                cancellation,
                &mut TypedFactPageVisitor::new(&mut callback),
            )?;
            if stopped || !outcome.is_exhausted() || cancellation.is_cancelled() {
                forward_open_reasons.push("forward interface nomination was stopped");
                complete = false;
            }
            for nomination in nominations {
                if cancellation.is_cancelled() || !session.scope_steps(1) {
                    forward_open_reasons.push("forward interface nomination was stopped");
                    complete = false;
                    break;
                }
                let Some(name) = names_by_identity.get(&nomination.identity_id) else {
                    forward_open_reasons.push("forward nomination name is unavailable");
                    complete = false;
                    continue;
                };
                let Some(role) =
                    self.go_source_role_for_mount(context_id, nomination.mount, cancellation)?
                else {
                    forward_open_reasons.push("forward nomination role is unavailable");
                    complete = false;
                    continue;
                };
                if role != "go" && role != source_role {
                    continue;
                }
                let mut statement =
                    connection.prepare_cached(GO_METHOD_INTERFACE_OWNERS_SQL.as_str())?;
                let mut rows = statement.query(params![
                    nomination.mount.get(),
                    nomination.blob_id,
                    name,
                    context_id,
                    source_role
                ])?;
                while let Some(row) = rows.next()? {
                    if cancellation.is_cancelled() || !session.scope_steps(1) {
                        forward_open_reasons.push("forward interface owner read was stopped");
                        complete = false;
                        break;
                    }
                    candidates.insert(SemanticId::local(
                        nomination.mount.get(),
                        row.get::<_, u32>(0)?,
                    ));
                }
            }
        }
        // The inverse embedding relation expands interface targets whose own
        // method rows are absent because they inherit all their methods.
        let mut ordered_candidates = candidates.iter().copied().collect::<Vec<_>>();
        ordered_candidates.sort_unstable();
        let mut queue = std::collections::VecDeque::from(ordered_candidates);
        let mut expanded = std::collections::HashSet::new();
        while let Some(interface) = queue.pop_front() {
            if !expanded.insert(interface) {
                continue;
            }
            if cancellation.is_cancelled() || !session.scope_steps(1) {
                forward_open_reasons.push("forward interface target closure was stopped");
                complete = false;
                break;
            }
            let descendants = self.go_embedding_subtypes(
                context_id,
                source_role,
                interface,
                cancellation,
                session,
            )?;
            if !descendants.is_complete() || !descendants.ambiguous.is_empty() {
                forward_open_reasons.push("forward interface target closure is incomplete");
                complete = false;
            }
            for child in descendants
                .edges
                .into_iter()
                .chain(descendants.ambiguous)
                .chain(descendants.open)
            {
                if cancellation.is_cancelled() || !session.scope_steps(1) {
                    forward_open_reasons.push("forward interface target closure was stopped");
                    complete = false;
                    break;
                }
                match typed.go_member_declarations(&[child], cancellation)? {
                    Some(declarations) if declarations.iter().any(|d| d.definition == child && matches!(d.kind, crate::analyzer::resolution::GoMemberDeclarationKind::Interface { .. })) => {
                        candidates.insert(child);
                        queue.push_back(child);
                    }
                    Some(declarations) if declarations.iter().any(|d| d.definition == child) => {}
                    _ => {
                        forward_open_reasons.push("forward target kind is unavailable");
                        complete = false;
                    }
                }
            }
        }
        candidates.extend(scan.empty.iter().copied());
        let forms: &[u32] = &[0];
        let mut candidates = candidates.into_iter().collect::<Vec<_>>();
        candidates.sort_unstable();
        for interface in candidates {
            if interface == definition {
                continue;
            }
            // Nomination rows are only candidates. The selected interface
            // method inventory, including inherited methods, owns the proof
            // that this target's contract was fully enumerated.
            match self.go_interface_method_inventory(
                context_id,
                source_role,
                interface,
                cancellation,
                session,
            )? {
                Some(inventory) if inventory.complete => {}
                Some(_) => {
                    forward_open_reasons
                        .push("forward candidate interface inventory is incomplete");
                    complete = false;
                }
                None => {
                    forward_open_reasons
                        .push("forward candidate interface inventory is unavailable");
                    complete = false;
                }
            }
            for &form in forms {
                if cancellation.is_cancelled() || !session.observe_cancellation() {
                    forward_open_reasons.push("forward satisfaction was stopped");
                    complete = false;
                    break;
                }
                let receiver =
                    crate::analyzer::resolution::ResolutionTypeRef::new(definition, form);
                match self.go_selected_type_satisfaction(
                    context_id,
                    source_role,
                    receiver,
                    interface,
                    cancellation,
                    session,
                )? {
                    Some(result) if result.outcome == GoMethodSatisfaction::Satisfies => {
                        answer.parents.push(GoDirectSupertype {
                            origin: GoSupertypeOrigin::Structural,
                            targets: vec![interface],
                            completion: ResolutionCompletion::Complete,
                            open_reason: None,
                        });
                        break;
                    }
                    Some(result) if result.outcome == GoMethodSatisfaction::DoesNotSatisfy => {}
                    Some(result) => {
                        if let GoMethodSatisfaction::Inconclusive(reason) = result.outcome {
                            forward_open_reasons.push(reason);
                        }
                        complete = false;
                    }
                    None => {
                        forward_open_reasons.push("forward satisfaction context is unavailable");
                        complete = false;
                    }
                }
            }
        }
        if cancellation.is_cancelled() || !session.observe_cancellation() {
            forward_open_reasons.push("forward satisfaction was stopped");
            complete = false;
        }
        if !complete {
            forward_open_reasons.push("forward candidate coverage is incomplete");
        }
        answer.forward_satisfaction_enumerated = complete && forward_open_reasons.is_empty();
        answer.forward_open_reasons = forward_open_reasons;
        Ok(answer)
    }

    fn go_direct_embeddings(
        &self,
        context_id: i64,
        source_role: &str,
        definition: SemanticId,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<GoDirectSupertypeAnswer> {
        let mut answer = GoDirectSupertypeAnswer {
            parents: Vec::new(),
            open_reasons: Vec::new(),
            forward_satisfaction_enumerated: false,
            forward_open_reasons: Vec::new(),
        };
        if cancellation.is_cancelled() || !session.scope_steps(1) {
            answer
                .open_reasons
                .push("hierarchy request cancelled or exhausted its budget");
            return Ok(answer);
        }
        let (Some(ordinal), Some(key)) = (definition.ordinal(), definition.local_key()) else {
            answer
                .open_reasons
                .push("type has no selected declaration identity");
            return Ok(answer);
        };
        match self.go_type_supports(context_id, source_role, definition, cancellation)? {
            GoTypeSupport::Supported => {}
            GoTypeSupport::Open => {
                answer
                    .open_reasons
                    .push("alias endpoint has no selected declaration identity");
                return Ok(answer);
            }
            GoTypeSupport::Unsupported => {
                answer
                    .open_reasons
                    .push("type has no selected declaration identity");
                return Ok(answer);
            }
        }
        let mount = self
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let path = mount.persisted_relative_path();
        let connection = self.ready.inventory.connection();
        let mut statement = connection.prepare_cached(GO_DIRECT_EMBEDDINGS_SQL.as_str())?;
        let embedded = statement
            .query_map(params![ordinal, key, context_id, source_role], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        let mut references = Vec::new();
        for (blob_id, type_id) in embedded {
            if cancellation.is_cancelled() || !session.scope_steps(1) {
                answer
                    .open_reasons
                    .push("hierarchy request cancelled or exhausted its budget");
                return Ok(answer);
            }
            let Some(type_id) = type_id else {
                answer.parents.push(GoDirectSupertype {
                    origin: GoSupertypeOrigin::UnresolvedEmbedding,
                    targets: Vec::new(),
                    completion: ResolutionCompletion::Complete,
                    open_reason: Some("embedded type has no selected type term"),
                });
                continue;
            };
            let mut statement = connection.prepare_cached(GO_EMBEDDED_REFERENCE_SQL.as_str())?;
            let sites = statement
                .query_map(params![blob_id, type_id], |row| row.get::<_, u32>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if sites.len() != 1 {
                answer.parents.push(GoDirectSupertype {
                    origin: GoSupertypeOrigin::UnresolvedEmbedding,
                    targets: Vec::new(),
                    completion: ResolutionCompletion::Complete,
                    open_reason: Some("embedded type has no unique selected native reference"),
                });
                continue;
            }
            references.push(SemanticId::local(ordinal, sites[0]));
        }
        if references.is_empty() {
            if cancellation.is_cancelled() {
                answer
                    .open_reasons
                    .push("hierarchy request cancelled or exhausted its budget");
            }
            return Ok(answer);
        }
        let prepared = match self.go_file_import_context_with_role(
            context_id,
            path,
            source_role,
            cancellation,
        )? {
            GoPreparedImportContextOutcome::Ready(prepared) => *prepared,
            GoPreparedImportContextOutcome::Cancelled => {
                answer.open_reasons.push("hierarchy request cancelled");
                return Ok(answer);
            }
            GoPreparedImportContextOutcome::Unavailable => {
                answer.open_reasons.push("Go import context is unavailable");
                return Ok(answer);
            }
        };
        let context = match self.prepare_context(
            prepared.context,
            cancellation,
            &SelectedResolutionContextMetrics,
        )? {
            SelectedResolutionContextValidationOutcome::Ready(context) => context,
            SelectedResolutionContextValidationOutcome::Cancelled => {
                answer.open_reasons.push("hierarchy request cancelled");
                return Ok(answer);
            }
        };
        if cancellation.is_cancelled() || !session.observe_cancellation() {
            answer.open_reasons.push("hierarchy request cancelled");
            return Ok(answer);
        }
        let Some(blueprint) = self.ready.publish_prepared_context(
            context,
            cancellation,
            session,
            Some(&self.jvm_context_blueprints),
            |blueprint| {
                if cancellation.is_cancelled() || !session.observe_cancellation() {
                    return Ok(ContextRegistrationOutcome::Cancelled);
                }
                self.ready.register_context(blueprint, cancellation)
            },
        )?
        else {
            answer.open_reasons.push("hierarchy request cancelled");
            return Ok(answer);
        };
        if cancellation.is_cancelled() || !session.observe_cancellation() {
            answer.open_reasons.push("hierarchy request cancelled");
            return Ok(answer);
        }
        let lexical = self.ready.lexical_source();
        let typed = self.ready.typed_source();
        let lexical = SeamProfiled::observing(&lexical);
        let typed = SeamProfiled::observing(&typed);
        let bindings = self.with_go_forward_operation(
            GoForwardOperationContext {
                blueprint: &blueprint,
                demand: prepared.demand,
                caller_path: path,
                lexical: &lexical,
                typed: &typed,
                cancellation,
                session,
            },
            None,
            |forward| {
                let mut bindings = Vec::new();
                for reference in references {
                    if cancellation.is_cancelled() || !session.scope_steps(1) {
                        bindings.push((reference, None));
                        continue;
                    }
                    let binding = forward.resolve_reference_with_metrics(
                        reference,
                        &mut ResolutionBatchMetrics::default(),
                    )?;
                    bindings.push((reference, Some(binding.binding().clone())));
                }
                Ok(bindings)
            },
        )?;
        for (reference, binding) in bindings {
            let Some(binding) = binding else {
                answer.parents.push(GoDirectSupertype {
                    origin: GoSupertypeOrigin::Embedding { reference },
                    targets: Vec::new(),
                    completion: ResolutionCompletion::Complete,
                    open_reason: Some("hierarchy request cancelled or exhausted its budget"),
                });
                continue;
            };
            let mut targets = binding.targets().to_vec();
            let mut support = GoTypeSupport::Supported;
            for &target in &targets {
                match self.go_type_supports(context_id, source_role, target, cancellation)? {
                    GoTypeSupport::Unsupported => support = GoTypeSupport::Unsupported,
                    GoTypeSupport::Open if support == GoTypeSupport::Supported => {
                        support = GoTypeSupport::Open;
                    }
                    _ => {}
                }
            }
            let mut alias_reason = None;
            if targets.len() == 1 && support == GoTypeSupport::Open {
                match self.go_alias_chain_terminal(
                    context_id,
                    source_role,
                    reference,
                    cancellation,
                    session,
                )? {
                    Ok(GoAliasTerminal::Selected(terminal)) => {
                        targets = vec![terminal];
                        support = GoTypeSupport::Supported;
                    }
                    Ok(GoAliasTerminal::Primitive) => {
                        alias_reason = Some("alias target is outside the mounted workspace");
                    }
                    Err(reason) => alias_reason = Some(reason),
                }
            }
            let open_reason = if binding.completion() != &ResolutionCompletion::Complete {
                Some("embedded type native resolution is incomplete")
            } else if targets.is_empty() {
                Some("embedded type has no selected target")
            } else if alias_reason.is_some() {
                alias_reason
            } else if support == GoTypeSupport::Open {
                Some("alias endpoint has no selected declaration identity")
            } else if support == GoTypeSupport::Unsupported {
                Some("embedded target has no selected declaration identity")
            } else {
                None
            };
            answer.parents.push(GoDirectSupertype {
                origin: GoSupertypeOrigin::Embedding { reference },
                targets,
                completion: binding.completion().clone(),
                open_reason,
            });
        }
        Ok(answer)
    }

    fn go_interface_alias_support(
        &self,
        definition: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<GoTypeSupport> {
        let declarations = self
            .ready
            .typed_source()
            .go_member_declarations(&[definition], cancellation)?;
        if cancellation.is_cancelled() {
            return Ok(GoTypeSupport::Open);
        }
        Ok(
            if declarations.is_some_and(|declarations| {
                declarations.iter().any(|declaration| {
                    declaration.definition == definition
                        && matches!(
                            declaration.kind,
                            crate::analyzer::resolution::GoMemberDeclarationKind::Interface { .. }
                        )
                })
            }) {
                GoTypeSupport::Supported
            } else {
                GoTypeSupport::Open
            },
        )
    }

    /// Check the selected declaration and its source role without enumerating
    /// any other type. A missing selected declaration is not a negative proof
    /// about an incomplete workspace selection.
    pub fn go_type_supports(
        &self,
        context_id: i64,
        source_role: &str,
        definition: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<GoTypeSupport> {
        if cancellation.is_cancelled() {
            return Ok(GoTypeSupport::Open);
        }
        let (Some(ordinal), Some(key)) = (definition.ordinal(), definition.local_key()) else {
            return Ok(GoTypeSupport::Unsupported);
        };
        let row: Option<i64> = self
            .ready
            .inventory
            .connection()
            .prepare_cached(GO_TYPE_SUPPORT_SQL.as_str())?
            .query_row(params![ordinal, key, context_id, source_role], |row| {
                row.get(0)
            })
            .optional()?;
        if cancellation.is_cancelled() {
            return Ok(GoTypeSupport::Open);
        }
        if row == Some(1) {
            return self.go_interface_alias_support(definition, cancellation);
        }
        if row.is_none() {
            let alias: Option<i64> = self
                .ready
                .inventory
                .connection()
                .prepare_cached(GO_ALIAS_WITHOUT_BRIDGE_SQL.as_str())?
                .query_row(params![ordinal, key, context_id, source_role], |row| {
                    row.get(0)
                })
                .optional()?;
            if alias.is_some() {
                return self.go_interface_alias_support(definition, cancellation);
            }
        }
        if cancellation.is_cancelled() {
            return Ok(GoTypeSupport::Open);
        }
        Ok(match row {
            Some(0) => GoTypeSupport::Supported,
            Some(_) => GoTypeSupport::Open,
            None => GoTypeSupport::Unsupported,
        })
    }
}

/// Keyed by mount and semantic definition. The selected file lookup is
/// correlated to that mount, so SQLite need not materialize the source view.
pub(crate) static GO_TYPE_SUPPORT_SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(
    || {
        format!(
            r#"SELECT CASE WHEN alias.declaration_id IS NOT NULL THEN 1 ELSE 0 END
               FROM temp.selected_resolution_mounts AS mount
               JOIN temp.selected_resolution_scope_mounts AS scope
                 ON scope.mount_ordinal=mount.mount_ordinal
               JOIN main.resolution_semantic_sites AS semantic
                 ON semantic.blob_id=mount.blob_id AND semantic.semantic_key=?2
                AND semantic.semantic_role='definition'
               JOIN main.source_native_declaration_bridges AS bridge
                 ON bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site
               LEFT JOIN main.source_go_type_declarations AS declaration
                 ON declaration.blob_id=bridge.blob_id
                AND declaration.declaration_id=bridge.declaration_id
               LEFT JOIN main.source_go_aliases AS alias
                 ON alias.blob_id=bridge.blob_id
                AND alias.declaration_id=bridge.declaration_id
               JOIN ({}) AS file ON file.file_version_id=coalesce(mount.file_version_id,
                 (SELECT placement.file_version_id FROM temp.selected_go_transient_placements AS placement
                  WHERE placement.mount_ordinal=mount.mount_ordinal))
                AND file.context_id=?3 AND file.source_role IN ('go',?4)
               WHERE mount.mount_ordinal=?1 AND mount.storage_language='go'
                 AND (declaration.declaration_id IS NOT NULL OR alias.declaration_id IS NOT NULL)
               LIMIT 1"#,
            super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str()
        )
    },
);

pub(crate) static GO_ALIAS_WITHOUT_BRIDGE_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            r#"SELECT 1
            FROM temp.selected_resolution_mounts mount
            JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=mount.mount_ordinal
            JOIN main.resolution_package_members member INDEXED BY resolution_package_members_definition
             ON member.blob_id=mount.blob_id AND member.definition_key=?2 AND member.namespace='type'
            JOIN main.resolution_semantic_catalog catalog ON catalog.blob_id=member.blob_id
             AND catalog.local_key=member.lookup_key
            JOIN main.resolution_identities identity ON identity.id=catalog.shared_identity
            JOIN main.source_go_aliases alias ON alias.blob_id=member.blob_id
             AND alias.name=identity.spelling
            JOIN ({}) file ON file.file_version_id=coalesce(mount.file_version_id,
              (SELECT placement.file_version_id FROM temp.selected_go_transient_placements placement
               WHERE placement.mount_ordinal=mount.mount_ordinal))
             AND file.context_id=?3 AND file.source_role IN ('go',?4)
            WHERE mount.mount_ordinal=?1 AND mount.storage_language='go' LIMIT 1"#,
            super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str()
        )
    });

pub(crate) static GO_DIRECT_EMBEDDINGS_SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(
    || {
        format!(
            r#"WITH owner(blob_id,type_id) AS (
          SELECT declaration.blob_id,declaration.type_id
          FROM temp.selected_resolution_mounts mount
          JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=mount.mount_ordinal
          JOIN main.resolution_semantic_sites semantic
            ON semantic.blob_id=mount.blob_id AND semantic.semantic_key=?2
           AND semantic.semantic_role='definition'
          JOIN main.source_native_declaration_bridges bridge
            ON bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site
          JOIN main.source_go_type_declarations declaration
            ON declaration.blob_id=bridge.blob_id AND declaration.declaration_id=bridge.declaration_id
          JOIN ({}) file ON file.file_version_id=coalesce(mount.file_version_id,
            (SELECT placement.file_version_id FROM temp.selected_go_transient_placements placement
             WHERE placement.mount_ordinal=mount.mount_ordinal))
           AND file.context_id=?3 AND file.source_role IN ('go',?4)
          WHERE mount.mount_ordinal=?1 AND mount.storage_language='go'
        ), embedded(blob_id,type_id,position) AS (
          SELECT element.blob_id,element.type_id,element.ordinal
          FROM owner JOIN main.source_go_embeddings element INDEXED BY source_go_embeddings_by_owner
            ON element.blob_id=owner.blob_id AND element.owner_type_id=owner.type_id
        )
        SELECT blob_id,type_id FROM embedded ORDER BY position,type_id"#,
            super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str()
        )
    },
);

/// A selected alias declaration's source target. The reference site is read
/// separately through GO_EMBEDDED_REFERENCE_SQL and resolved by the caller.
pub(crate) static GO_ALIAS_TARGET_TYPE_SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(
    || {
        format!(
            r#"SELECT alias.blob_id,alias.target_type_id
            FROM temp.selected_resolution_mounts mount
            JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=mount.mount_ordinal
            JOIN main.resolution_package_members member INDEXED BY resolution_package_members_definition
             ON member.blob_id=mount.blob_id AND member.definition_key=?2 AND member.namespace='type'
            JOIN main.resolution_semantic_catalog catalog ON catalog.blob_id=member.blob_id
             AND catalog.local_key=member.lookup_key
            JOIN main.resolution_identities identity ON identity.id=catalog.shared_identity
            JOIN main.source_go_aliases alias ON alias.blob_id=member.blob_id
             AND alias.name=identity.spelling
            JOIN ({}) file ON file.file_version_id=coalesce(mount.file_version_id,
              (SELECT placement.file_version_id FROM temp.selected_go_transient_placements placement
               WHERE placement.mount_ordinal=mount.mount_ordinal))
             AND file.context_id=?3 AND file.source_role IN ('go',?4)
            WHERE mount.mount_ordinal=?1 AND mount.storage_language='go'"#,
            super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str()
        )
    },
);

/// The wrapper depth at which `go_source_type_head_sql` stops. A head row at
/// this depth that is still a traversable wrapper means the walk was cut.
const GO_SOURCE_TYPE_HEAD_DEPTH: usize = 32;

/// Walk source type wrappers structurally from a caller-supplied seed. Carry
/// an optional owner identity for inverse nomination, while the same walk
/// serves reference mapping and alias-literal classification.
pub(crate) fn go_source_type_head_sql(seed: &str, carried_column: Option<&str>) -> String {
    let (extra_column, extra_value) = carried_column
        .map(|column| (format!(",{column}"), format!(",head.{column}")))
        .unwrap_or_default();
    let extra_seed = carried_column
        .map(|column| format!(",input.{column}"))
        .unwrap_or_default();
    format!(
        r#"WITH RECURSIVE input(blob_id,type_id,depth{extra_column}) AS ({seed}),
head(blob_id,type_id,depth,pointer_hops{extra_column}) AS (
  SELECT input.blob_id,input.type_id,input.depth,0{extra_seed} FROM input
  UNION ALL
  SELECT head.blob_id,child.child1,head.depth+1,
         head.pointer_hops+(child.kind=1){extra_value} FROM head
  JOIN main.source_go_types child ON child.blob_id=head.blob_id AND child.type_id=head.type_id
  WHERE child.kind IN (1,7) AND child.child1 IS NOT NULL AND head.depth<{GO_SOURCE_TYPE_HEAD_DEPTH}
  UNION ALL
  SELECT head.blob_id,element.child_id,head.depth+1,head.pointer_hops{extra_value} FROM head
  JOIN main.source_go_types wrapper ON wrapper.blob_id=head.blob_id AND wrapper.type_id=head.type_id
   AND wrapper.kind IN (8,9,10)
  JOIN main.source_go_type_children element ON element.blob_id=wrapper.blob_id
   AND element.type_id=wrapper.type_id AND element.ordinal=0
  WHERE head.depth<{GO_SOURCE_TYPE_HEAD_DEPTH} AND NOT EXISTS (
    SELECT 1 FROM main.source_go_type_children sibling
    WHERE sibling.blob_id=wrapper.blob_id AND sibling.type_id=wrapper.type_id AND sibling.ordinal=1)
)"#
    )
}

// The alias identity transfer connects its definition to the synthetic
// literal definition. The literal retains ownership; readers project its
// exact method key/name pair onto the selected alias.
pub(crate) fn go_alias_literal_method_pairs_sql(seed: &str) -> String {
    format!(
        r#"{}, alias_method_pairs AS (SELECT DISTINCT head.blob_id, alias_member.definition_key AS alias_key,
                 owner.definition_semantic_key AS method_key, owner.member_name
          FROM head
          JOIN main.source_go_types literal ON literal.blob_id=head.blob_id
           AND literal.type_id=head.type_id AND literal.kind=13
           AND head.pointer_hops=0
          JOIN main.source_go_aliases alias ON alias.blob_id=head.blob_id
           AND alias.declaration_id=head.alias_declaration_id
          JOIN main.resolution_package_members alias_member
           ON alias_member.blob_id=alias.blob_id AND alias_member.namespace='type'
          JOIN main.resolution_semantic_catalog alias_lookup
           ON alias_lookup.blob_id=alias_member.blob_id
           AND alias_lookup.local_key=alias_member.lookup_key
          JOIN main.resolution_identities alias_identity
           ON alias_identity.id=alias_lookup.shared_identity
           AND alias_identity.spelling=alias.name
          -- A duplicate source alias name cannot identify which target the
          -- package-member definition denotes.
          AND NOT EXISTS (SELECT 1 FROM main.source_go_aliases other
           WHERE other.blob_id=alias.blob_id AND other.name=alias.name
             AND other.declaration_id<>alias.declaration_id)
          JOIN main.resolution_declaration_types alias_type
           ON alias_type.blob_id=alias_member.blob_id
           AND alias_type.definition=alias_member.definition_key AND alias_type.role=3
          JOIN main.resolution_type_transfers transfer
           ON transfer.blob_id=alias_type.blob_id
           AND transfer.target_slot=alias_type.slot AND transfer.kind=0
           AND transfer.indirection_delta=0
          JOIN main.resolution_declaration_types literal_type
           ON literal_type.blob_id=transfer.blob_id
           AND literal_type.slot=transfer.source_slot AND literal_type.role=3
          -- The literal owns embedded edges too; direct methods alone cannot
          -- close an alias whose literal has an embedded term.
          AND NOT EXISTS (SELECT 1 FROM main.resolution_supertypes embedded
           WHERE embedded.blob_id=literal_type.blob_id
             AND embedded.definition=literal_type.definition)
          -- Type-set and constraint terms publish this gap on the literal
          -- site without a supertype row. They cannot close a method set.
          AND NOT EXISTS (SELECT 1 FROM main.resolution_semantic_sites literal_site
           JOIN main.resolution_gap_reasons reason ON reason.blob_id=literal_site.blob_id
            AND reason.site=literal_site.source_site AND reason.origin={}
           WHERE literal_site.blob_id=literal_type.blob_id
             AND literal_site.semantic_key=literal_type.definition
             AND literal_site.semantic_role='definition')
          JOIN main.resolution_member_owner_properties owner
           ON owner.blob_id=literal_type.blob_id
           AND owner.owner_definition_semantic_key=literal_type.definition
           AND owner.member_kind='method')"#,
        go_source_type_head_sql(seed, Some("alias_declaration_id")),
        crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(
            crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                ResolutionGapKind::UnsupportedHierarchyTraversal,
            ),
        )
    )
}

// A relation-42 method owned by an anonymous literal remains open unless the
// exact alias/method pair was projected. Named interfaces have a named source declaration.
pub(crate) static GO_UNPROJECTED_INTERFACE_METHOD_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            r#"{}
SELECT EXISTS (
 SELECT 1 FROM main.resolution_member_owner_properties owner
 JOIN main.resolution_declaration_types literal_type
  ON literal_type.blob_id=owner.blob_id
  AND literal_type.definition=owner.owner_definition_semantic_key
  AND literal_type.role=3
 JOIN main.resolution_semantic_sites literal_site
  ON literal_site.blob_id=owner.blob_id
  AND literal_site.semantic_key=owner.owner_definition_semantic_key
  AND literal_site.semantic_role='definition'
 LEFT JOIN main.source_native_declaration_bridges bridge
  ON bridge.blob_id=literal_site.blob_id
  AND bridge.source_site=literal_site.source_site
 LEFT JOIN main.source_declarations named
  ON named.blob_id=bridge.blob_id
  AND named.declaration_id=bridge.declaration_id
  AND named.name_occurrence_id IS NOT NULL
 WHERE owner.blob_id=?1 AND owner.member_name=?2
  AND owner.member_kind='method' AND named.declaration_id IS NULL
  AND NOT EXISTS (SELECT 1 FROM alias_method_pairs pair
   WHERE pair.blob_id=owner.blob_id
    AND pair.method_key=owner.definition_semantic_key)
)"#,
            go_alias_literal_method_pairs_sql(
                "SELECT alias.blob_id,alias.target_type_id,0,alias.declaration_id FROM main.source_go_aliases alias WHERE alias.blob_id=?1 AND alias.target_type_id IS NOT NULL"
            )
        )
    });

pub(crate) static GO_EMBEDDED_REFERENCE_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            "{}{}",
            go_source_type_head_sql("SELECT ?1,?2,0", None),
            r#", named AS (
  SELECT type.occurrence_id,COALESCE(terminal.name,first.name) AS name
  FROM head JOIN main.source_go_types type ON type.blob_id=?1 AND type.type_id=head.type_id
  LEFT JOIN main.source_go_type_names first ON first.blob_id=type.blob_id
    AND first.type_id=type.type_id AND first.ordinal=0
  LEFT JOIN main.source_go_type_names terminal ON terminal.blob_id=type.blob_id
    AND terminal.type_id=type.type_id AND terminal.ordinal=1
  WHERE type.kind=0
), span AS (
  SELECT CAST(json_extract(occurrence.value,'$[0]') AS INTEGER) AS start_byte,
         CAST(json_extract(occurrence.value,'$[1]') AS INTEGER) AS end_byte,
         named.name
  FROM named JOIN main.source_occurrence_arenas arena ON arena.blob_id=?1
  JOIN json_each(arena.spans) occurrence ON occurrence.key=named.occurrence_id
)
SELECT DISTINCT site.site
FROM span JOIN main.resolution_sites site ON site.blob_id=?1 AND site.role=0
 AND site.start_byte>=span.start_byte AND site.end_byte<=span.end_byte
JOIN main.resolution_paths path INDEXED BY resolution_paths_forward
  ON path.blob_id=site.blob_id AND path.start_node=site.site
JOIN main.resolution_identities identity ON identity.id=CASE WHEN path.end_node=-1
  THEN path.root_terminal ELSE path.end_lead_identity END AND identity.spelling=span.name
ORDER BY site.site
"#
        )
    });

pub(crate) static GO_INVERSE_EMBEDDING_OWNERS_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            "{}{}",
            go_source_type_head_sql(
                "SELECT embedding.blob_id,embedding.type_id,0,embedding.owner_type_id FROM main.source_go_embeddings embedding WHERE embedding.blob_id=?1",
                Some("owner_type_id"),
            ),
            r#"
SELECT DISTINCT semantic.semantic_key
FROM head
JOIN main.source_go_types type ON type.blob_id=?1 AND type.type_id=head.type_id AND type.kind=0
JOIN main.source_go_type_names name ON name.blob_id=type.blob_id
 AND name.type_id=type.type_id AND name.name=?2
 AND NOT EXISTS (SELECT 1 FROM main.source_go_type_names later
   WHERE later.blob_id=name.blob_id AND later.type_id=name.type_id AND later.ordinal>name.ordinal)
JOIN main.source_go_type_declarations owner ON owner.blob_id=type.blob_id
 AND owner.type_id=head.owner_type_id
JOIN main.source_native_declaration_bridges bridge ON bridge.blob_id=owner.blob_id
 AND bridge.declaration_id=owner.declaration_id
JOIN main.resolution_semantic_sites semantic ON semantic.blob_id=bridge.blob_id
 AND semantic.source_site=bridge.source_site AND semantic.semantic_role='definition'
ORDER BY semantic.semantic_key
"#
        )
    });

pub(crate) static GO_INVERSE_ALIAS_NOMINEES_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            "{}{}",
            go_source_type_head_sql(
                "SELECT alias.blob_id,alias.target_type_id,0,alias.declaration_id FROM main.source_go_aliases alias WHERE alias.blob_id=?1 AND alias.target_type_id IS NOT NULL",
                Some("declaration_id"),
            ),
            r#"
SELECT DISTINCT alias.declaration_id,alias.name,alias.target_type_id
FROM head
JOIN main.source_go_types type ON type.blob_id=?1 AND type.type_id=head.type_id AND type.kind=0
JOIN main.source_go_type_names name ON name.blob_id=type.blob_id
 AND name.type_id=type.type_id AND name.name=?2
 AND NOT EXISTS (SELECT 1 FROM main.source_go_type_names later
   WHERE later.blob_id=name.blob_id AND later.type_id=name.type_id AND later.ordinal>name.ordinal)
JOIN main.source_go_aliases alias ON alias.blob_id=?1 AND alias.declaration_id=head.declaration_id
ORDER BY alias.declaration_id
"#
        )
    });

pub(crate) const GO_METHOD_LOOKUP_COUNT_SQL: &str = r#"
SELECT COUNT(*) FROM main.resolution_typed_fact_lookups
 INDEXED BY resolution_typed_fact_lookups_identity
WHERE relation=22 AND identity_id=?1
"#;

pub(crate) static GO_METHOD_INTERFACE_OWNERS_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            r#"{}
            SELECT DISTINCT semantic.semantic_key
            FROM temp.selected_resolution_mounts mount
            JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=mount.mount_ordinal
            JOIN main.source_go_type_declarations declaration ON declaration.blob_id=mount.blob_id
            JOIN main.source_go_types type ON type.blob_id=declaration.blob_id
             AND type.type_id=declaration.type_id AND type.kind=13
            JOIN main.source_go_callables method INDEXED BY source_go_callables_by_owner
             ON method.blob_id=declaration.blob_id AND method.owner_type_id=declaration.type_id
             AND method.name=?3 AND method.is_method=1
            JOIN main.source_native_declaration_bridges bridge ON bridge.blob_id=declaration.blob_id
             AND bridge.declaration_id=declaration.declaration_id
            JOIN main.resolution_semantic_sites semantic ON semantic.blob_id=bridge.blob_id
             AND semantic.source_site=bridge.source_site AND semantic.semantic_role='definition'
            JOIN ({}) file ON file.file_version_id=coalesce(mount.file_version_id,
              (SELECT placement.file_version_id FROM temp.selected_go_transient_placements placement
               WHERE placement.mount_ordinal=mount.mount_ordinal))
             AND file.context_id=?4 AND file.source_role IN ('go',?5)
            WHERE mount.mount_ordinal=?1 AND mount.blob_id=?2 AND mount.storage_language='go'
            UNION
            SELECT pair.alias_key
            FROM alias_method_pairs pair
            JOIN temp.selected_resolution_mounts mount ON mount.blob_id=pair.blob_id
             AND mount.mount_ordinal=?1 AND mount.storage_language='go'
            JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=mount.mount_ordinal
            JOIN ({}) file ON file.file_version_id=coalesce(mount.file_version_id,
              (SELECT placement.file_version_id FROM temp.selected_go_transient_placements placement
               WHERE placement.mount_ordinal=mount.mount_ordinal))
             AND file.context_id=?4 AND file.source_role IN ('go',?5)
            WHERE pair.member_name=?3
            ORDER BY 1"#,
            go_alias_literal_method_pairs_sql(
                "SELECT alias.blob_id,alias.target_type_id,0,alias.declaration_id FROM main.source_go_aliases alias WHERE alias.blob_id=?2 AND alias.target_type_id IS NOT NULL"
            ),
            super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str(),
            super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str()
        )
    });

// Exact selected source ownership is independent of a named interface bridge.
const GO_ANONYMOUS_INTERFACE_METHOD_SQL: &str = r#"
SELECT EXISTS(SELECT 1 FROM temp.selected_resolution_mounts mount
 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=mount.mount_ordinal
 JOIN main.resolution_semantic_sites semantic ON semantic.blob_id=mount.blob_id
  AND semantic.semantic_key=?2 AND semantic.semantic_role='definition'
 JOIN main.source_native_declaration_bridges bridge ON bridge.blob_id=semantic.blob_id
  AND bridge.source_site=semantic.source_site
 JOIN main.source_go_callables callable ON callable.blob_id=bridge.blob_id
  AND callable.declaration_id=bridge.declaration_id AND callable.is_method=1
 JOIN main.source_go_types owner ON owner.blob_id=callable.blob_id
  AND owner.type_id=callable.owner_type_id AND owner.kind=13
 WHERE mount.mount_ordinal=?1 AND mount.storage_language='go')"#;

pub(crate) static GO_INTERFACE_OWNER_FOR_METHOD_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            r#"{}
            SELECT owner_semantic.semantic_key
            FROM temp.selected_resolution_mounts mount
            JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=mount.mount_ordinal
            JOIN main.resolution_semantic_sites method_semantic ON method_semantic.blob_id=mount.blob_id
             AND method_semantic.semantic_key=?2 AND method_semantic.semantic_role='definition'
            JOIN main.source_native_declaration_bridges method_bridge
             ON method_bridge.blob_id=method_semantic.blob_id
             AND method_bridge.source_site=method_semantic.source_site
            JOIN main.source_go_callables method ON method.blob_id=method_bridge.blob_id
             AND method.declaration_id=method_bridge.declaration_id AND method.is_method=1
            JOIN main.source_go_types type ON type.blob_id=method.blob_id
             AND type.type_id=method.owner_type_id AND type.kind=13
            JOIN main.source_go_type_declarations owner ON owner.blob_id=type.blob_id
             AND owner.type_id=type.type_id
            JOIN main.source_native_declaration_bridges owner_bridge ON owner_bridge.blob_id=owner.blob_id
             AND owner_bridge.declaration_id=owner.declaration_id
            JOIN main.resolution_semantic_sites owner_semantic ON owner_semantic.blob_id=owner_bridge.blob_id
             AND owner_semantic.source_site=owner_bridge.source_site AND owner_semantic.semantic_role='definition'
            JOIN ({}) file ON file.file_version_id=coalesce(mount.file_version_id,
              (SELECT placement.file_version_id FROM temp.selected_go_transient_placements placement
               WHERE placement.mount_ordinal=mount.mount_ordinal))
             AND file.context_id=?3 AND file.source_role IN ('go',?4)
            WHERE mount.mount_ordinal=?1 AND mount.storage_language='go'
            UNION
            SELECT pair.alias_key
            FROM alias_method_pairs pair
            JOIN temp.selected_resolution_mounts mount ON mount.blob_id=pair.blob_id
             AND mount.mount_ordinal=?1 AND mount.storage_language='go'
            JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=mount.mount_ordinal
            JOIN ({}) file ON file.file_version_id=coalesce(mount.file_version_id,
              (SELECT placement.file_version_id FROM temp.selected_go_transient_placements placement
               WHERE placement.mount_ordinal=mount.mount_ordinal))
             AND file.context_id=?3 AND file.source_role IN ('go',?4)
            WHERE pair.method_key=?2
            LIMIT 1"#,
            go_alias_literal_method_pairs_sql(
                "SELECT alias.blob_id,alias.target_type_id,0,alias.declaration_id FROM temp.selected_resolution_mounts seed_mount JOIN main.source_go_aliases alias ON alias.blob_id=seed_mount.blob_id WHERE seed_mount.mount_ordinal=?1 AND alias.target_type_id IS NOT NULL"
            ),
            super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str(),
            super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str()
        )
    });

pub(crate) static GO_HIERARCHY_METHOD_IDENTITY_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            r#"{}
            SELECT callable.name,package.package_id
            FROM temp.selected_resolution_mounts mount
            JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=mount.mount_ordinal
            JOIN main.resolution_semantic_sites semantic ON semantic.blob_id=mount.blob_id
             AND semantic.semantic_key=?2 AND semantic.semantic_role='definition'
            JOIN main.source_native_declaration_bridges bridge ON bridge.blob_id=semantic.blob_id
             AND bridge.source_site=semantic.source_site
            JOIN main.source_go_callables callable ON callable.blob_id=bridge.blob_id
             AND callable.declaration_id=bridge.declaration_id AND callable.is_method=1
            JOIN ({}) file ON file.file_version_id=coalesce(mount.file_version_id,
              (SELECT placement.file_version_id FROM temp.selected_go_transient_placements placement
               WHERE placement.mount_ordinal=mount.mount_ordinal))
             AND file.context_id=?3 AND file.source_role IN ('go',?4)
            JOIN main.go_package_instances package ON package.package_id=file.package_id
             AND package.context_id=?3
            WHERE mount.mount_ordinal=?1 AND mount.storage_language='go'
            UNION
            SELECT pair.member_name,package.package_id
            FROM alias_method_pairs pair
            JOIN temp.selected_resolution_mounts mount ON mount.blob_id=pair.blob_id
             AND mount.mount_ordinal=?1 AND mount.storage_language='go'
            JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=mount.mount_ordinal
            JOIN ({}) file ON file.file_version_id=coalesce(mount.file_version_id,
              (SELECT placement.file_version_id FROM temp.selected_go_transient_placements placement
               WHERE placement.mount_ordinal=mount.mount_ordinal))
             AND file.context_id=?3 AND file.source_role IN ('go',?4)
            JOIN main.go_package_instances package ON package.package_id=file.package_id
             AND package.context_id=?3
            WHERE pair.method_key=?2
            LIMIT 1"#,
            go_alias_literal_method_pairs_sql(
                "SELECT alias.blob_id,alias.target_type_id,0,alias.declaration_id FROM temp.selected_resolution_mounts seed_mount JOIN main.source_go_aliases alias ON alias.blob_id=seed_mount.blob_id WHERE seed_mount.mount_ordinal=?1 AND alias.target_type_id IS NOT NULL"
            ),
            super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str(),
            super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str()
        )
    });
