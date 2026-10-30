//! Bounded typed-fact reads for one exact selected resolution inventory.
//!
//! The source borrows the retained connection and TEMP mount inventory opened
//! by `resolution_selection`. Every keyed request is translated back to exact
//! selected storage coordinates through the operation-local `MountRebaser`;
//! shared semantics are expanded only across the selected mounts. SQL remains
//! selected-first and keyset-paged, and parent rows are emitted only after all
//! ordered children and completion reasons have been decoded.

pub(super) mod external_owners;
pub(super) mod go_members;
mod go_model;
pub(super) mod java_access;
pub(super) mod java_inheritance;

use std::collections::BTreeSet;

use std::rc::Rc;

use rusqlite::types::Value;

use rusqlite::Connection;
use rusqlite::OptionalExtension;
use rusqlite::Row;
use rusqlite::params_from_iter;

use crate::CancellationToken;

use crate::analyzer::Language;

use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;

use crate::analyzer::resolution::BindingFragmentId;
use crate::analyzer::resolution::BindingNodeId;
use crate::analyzer::resolution::DeferredMemberOwnerLookupName;
use crate::analyzer::resolution::LoweredBindingProjection;
use crate::analyzer::resolution::LoweredCallApplicabilityObligation;
use crate::analyzer::resolution::LoweredCallableSignatureProperty;
use crate::analyzer::resolution::LoweredConstructionRequirementProperty;
use crate::analyzer::resolution::LoweredDeclarationTypeProperty;
use crate::analyzer::resolution::LoweredDeclarationVisibilityProperty;
use crate::analyzer::resolution::LoweredDeclaredTypeArgument;
use crate::analyzer::resolution::LoweredDeferredMemberOwner;
use crate::analyzer::resolution::LoweredDefinitionPropertyGap;
use crate::analyzer::resolution::LoweredGenericFormal;
use crate::analyzer::resolution::LoweredGenericFormalDefault;
use crate::analyzer::resolution::LoweredGenericTypeAliasParameter;
use crate::analyzer::resolution::LoweredIntrinsicSeed;
use crate::analyzer::resolution::LoweredIntrinsicTypeDescriptor;
use crate::analyzer::resolution::LoweredMemberOwnerProperty;
use crate::analyzer::resolution::LoweredMemberScopeProperty;
use crate::analyzer::resolution::LoweredRustDeclarationAuthority;
use crate::analyzer::resolution::LoweredRustReferenceContext;
use crate::analyzer::resolution::LoweredSupertypeProperty;
use crate::analyzer::resolution::LoweredTypeArgument;
use crate::analyzer::resolution::LoweredTypeComponent;
use crate::analyzer::resolution::LoweredTypeProduction;
use crate::analyzer::resolution::LoweredTypeTransfer;
use crate::analyzer::resolution::LoweredTypedFrontier;
use crate::analyzer::resolution::LoweredUnderlyingType;
use crate::analyzer::resolution::MAX_TYPED_FACT_ROWS_PER_PAGE;
use crate::analyzer::resolution::NamedArgumentLabel;
use crate::analyzer::resolution::NamedArgumentLabelRead;
use crate::analyzer::resolution::PolledCompletionAccumulator;
use crate::analyzer::resolution::QualifiedRouteSlotLookup;
use crate::analyzer::resolution::ResolutionCompletion;
use crate::analyzer::resolution::ResolutionIncompleteReason;
use crate::analyzer::resolution::RustImplementedTraits;
use crate::analyzer::resolution::SelectedGapReasonProvenance;
use crate::analyzer::resolution::SelectedNodeProvenance;
use crate::analyzer::resolution::SelectedQualifiedRoute;
use crate::analyzer::resolution::SelectedResolutionMountOrdinal;
use crate::analyzer::resolution::SelectedSemanticProvenance;
use crate::analyzer::resolution::SelectedTypeFrontierCompletion;
use crate::analyzer::resolution::SelectedTypedFactSource;
use crate::analyzer::resolution::SelectedTypedRow;
use crate::analyzer::resolution::SemanticId;
use crate::analyzer::resolution::SharedNameInterner;
use crate::analyzer::resolution::TypedFactPageVisitor;
use crate::analyzer::resolution::TypedFactReadOutcome;
use crate::analyzer::resolution::TypedFactRequest;
use crate::analyzer::resolution::language_identity_domain;
use crate::analyzer::resolution::language_type_qualifiers_search_companion_members;
use crate::analyzer::resolution::{CompanionTypeRelation, JvmAliasProperty};

use super::resolution::TypedFactRelation;
use super::resolution::json_array;
use super::resolution::json_pair_array;
use super::resolution::mount_ordinal;
use super::resolution::nonnegative_i64;
use super::resolution::read_resolution_statement;
use super::resolution::require_selected_mount_record;

use super::resolution_authority::SelectedResolutionAuthority;

use super::resolution_prepare::rust_authority;

use super::resolution_prepare::typed_rows;
use super::resolution_prepare::typed_rows::TypedRowContext;

use super::resolution_selection::SelectedResolutionMountInventory;
use super::resolution_selection::SelectedResolutionMountRecord;
use super::resolution_selection::SelectedResolutionReadStamp;

use super::Result as StoreResult;
use super::StoreError;

/// Indexed impl Target read shared by execution and planner pins.
pub(in crate::analyzer::store) const RUST_RECEIVER_IMPL_TARGETS_SQL: &str = "SELECT DISTINCT target_mount.mount_ordinal, target.semantic_key
FROM temp.selected_resolution_mounts AS owner_mount
CROSS JOIN resolution_rust_declaration_authorities AS owner
 ON owner.blob_id=owner_mount.blob_id AND owner.semantic_key=?2
CROSS JOIN resolution_unit_summary_members AS owner_member
 INDEXED BY resolution_unit_summary_members_blob
 ON owner_member.blob_id=owner.blob_id
AND owner_member.rel_path=owner_mount.persisted_relative_path
CROSS JOIN selected_rust_unit_summaries AS owner_unit
 ON owner_unit.summary_id=owner_member.summary_id
CROSS JOIN rust_resolution_unit_summary_exports AS export
 INDEXED BY rust_resolution_unit_summary_exports_declaration
 ON export.summary_id=owner_unit.summary_id
AND export.declaration_member_ordinal=owner_member.member_ordinal
AND export.declaration_site=owner.source_site
AND export.namespace='type' AND export.origin='declaration'
CROSS JOIN rust_resolution_unit_summary_trait_endpoints AS subject
 INDEXED BY rust_resolution_unit_summary_trait_endpoints_target
 ON subject.target_unit_key=owner_unit.unit_key
AND subject.target_module_path=export.module_path
AND subject.target_identity_id=export.identity_id
AND subject.endpoint_role='subject' AND subject.endpoint_state='resolved'
CROSS JOIN selected_rust_unit_summaries AS impl_unit
 ON impl_unit.summary_id=subject.summary_id
CROSS JOIN rust_resolution_unit_summary_trait_endpoints AS trait
 ON trait.summary_id=subject.summary_id AND trait.member_ordinal=subject.member_ordinal
AND trait.owner_module_path=subject.owner_module_path
AND trait.source_relation_key=subject.source_relation_key AND trait.endpoint_role='trait'
CROSS JOIN resolution_unit_summary_members AS impl_member
 ON impl_member.summary_id=subject.summary_id AND impl_member.member_ordinal=subject.member_ordinal
CROSS JOIN temp.selected_resolution_mounts AS target_mount
 ON target_mount.blob_id=impl_member.blob_id
AND target_mount.persisted_relative_path=impl_member.rel_path
AND target_mount.storage_language='rust'
CROSS JOIN source_rust_item_body_children AS child
 ON child.blob_id=impl_member.blob_id AND child.owner_declaration_id=subject.impl_declaration_id
CROSS JOIN resolution_rust_declaration_authorities AS target
 ON target.blob_id=child.blob_id AND target.declaration=child.declaration_id
CROSS JOIN resolution_deferred_member_owners AS member
 ON member.blob_id=target.blob_id AND member.definition=target.semantic_key
CROSS JOIN resolution_identities AS lookup ON lookup.id=member.lookup AND lookup.spelling='Target'
WHERE owner_mount.mount_ordinal=?1 AND child.syntax_kind='type_item' AND trait.endpoint_state='unresolved'";

pub(in crate::analyzer::store) const INVOCATION_ROLES_FOR_REFERENCES_SQL: &str = "SELECT role.site, role.role FROM json_each(?2) request \
     CROSS JOIN main.resolution_semantic_sites site ON site.blob_id=?1 \
         AND site.semantic_role='reference' AND site.semantic_key=request.value \
     CROSS JOIN main.resolution_invocation_roles role ON role.blob_id=site.blob_id \
         AND role.site=site.source_site";

// JSON request arrays have no corpus statistics. CROSS JOIN keeps the small
// request outermost even when SQLite estimates the corpus as cheaper (#5658).
pub(super) const GENERIC_PARAMETER_DECLARATIONS_SQL: &str = r#"
    SELECT json_extract(request.value, '$[0]'), json_extract(request.value, '$[1]')
    FROM json_each(?1) AS request
    CROSS JOIN temp.selected_resolution_mounts AS mount ON mount.mount_ordinal=json_extract(request.value, '$[0]')
    CROSS JOIN main.resolution_fragment_interiors AS interior
      ON interior.blob_id=mount.blob_id AND interior.lang=mount.storage_language
     AND interior.semantic_language=mount.semantic_language
     AND interior.producer_epoch=mount.producer_epoch AND interior.interior_digest=mount.interior_digest
     AND interior.publication_state='complete'
    CROSS JOIN main.resolution_semantic_sites AS semantic
      ON semantic.blob_id=interior.blob_id AND semantic.semantic_role='definition'
     AND semantic.semantic_key=json_extract(request.value, '$[1]') AND semantic.namespace='type'
    CROSS JOIN main.source_native_declaration_bridges AS bridge
      ON bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site
    CROSS JOIN main.source_declarations AS declaration
      ON declaration.blob_id=bridge.blob_id AND declaration.declaration_id=bridge.declaration_id
    WHERE declaration.lexical_kind='parameter'
"#;

// Enumerate the selected scope before probing any corpus publication.
pub(super) const QUALIFIED_ROUTE_MOUNTS_SQL: &str = r#"SELECT m.mount_ordinal
               FROM temp.selected_resolution_scope_mounts AS scope
               CROSS JOIN temp.selected_resolution_mounts AS m
 ON m.mount_ordinal = scope.mount_ordinal
               CROSS JOIN main.resolution_fragment_interiors AS interior
 ON interior.blob_id = m.blob_id
AND interior.lang = m.storage_language
AND interior.semantic_language = m.semantic_language
AND interior.producer_epoch = m.producer_epoch
AND interior.interior_digest = m.interior_digest
AND interior.publication_state = 'complete'
               WHERE EXISTS (
 SELECT 1 FROM main.resolution_typed_fact_lookups AS route
 WHERE route.blob_id = m.blob_id AND route.relation = ?1
               )
               ORDER BY m.mount_ordinal"#;

/// The one tier 1 family every typed read's membership comes from: which
/// blobs hold a fact of a named relation under an interned identity.
///
/// There is no name-mention default and no name-mention relation. Asking which
/// blobs *spell* a name returns most of the workspace for an ordinary member
/// name and is the wrong question for a typed read; the relation this family
/// is keyed on is the right one, and a read that has no relation has no
/// membership.
const TYPED_FACT_LOOKUP_FAMILY: &str = "resolution_typed_fact_lookups";

const PAGE_ROWS: usize = MAX_TYPED_FACT_ROWS_PER_PAGE;

#[doc(hidden)]
pub const FRONTIER_SOURCE_READY_SQL: &str =
    "SELECT 1 FROM main.source_fact_readiness WHERE blob_id=?1 AND available=1";

pub(super) trait GoDefinitionContextBinder {
    fn active_package(&self) -> Option<(i64, Option<&'static str>)>;

    fn bind_context(
        &self,
        ordinal: SelectedResolutionMountOrdinal,
        path: &str,
        candidates: &[SemanticId],
    ) -> StoreResult<Option<super::GoContextIdentity>>;
}

/// Operation-local typed reader over one retained selected inventory.
#[doc(hidden)]
pub struct SelectedResolutionTypedSource<'selection, 'store> {
    selection: &'selection SelectedResolutionMountInventory<'store>,
    implicit_environment: Option<i64>,
    implicit_language_version: Option<(u16, u16)>,
    authority: Rc<SelectedResolutionAuthority<'selection>>,
    context_identities: crate::analyzer::resolution::SelectedContextIdentities,
    external_providers: Vec<String>,
    model_authority: Option<
        std::sync::Arc<dyn super::resolution_operation::SelectedModelAuthority + Send + Sync>,
    >,
    external_models:
        Option<std::sync::Arc<crate::analyzer::semantic_model::ResolvedActiveSemanticModels>>,
    go_context_binder: Option<&'selection dyn GoDefinitionContextBinder>,
    go_owner_proofs: std::cell::RefCell<go_members::OwnerProofMemo>,
    external_signatures: std::cell::RefCell<external_owners::ExternalSignatureMemo>,
    // One classifier per opted-in storage language, not per mount or definition.
    namespace_classifiers: Vec<(
        String,
        Box<dyn super::language_support::NamespaceDefinitionClassifier>,
    )>,
}

impl<'selection, 'store> SelectedResolutionTypedSource<'selection, 'store> {
    #[doc(hidden)]
    pub fn new_on_demand(selection: &'selection SelectedResolutionMountInventory<'store>) -> Self {
        Self::with_authority(
            selection,
            Rc::new(SelectedResolutionAuthority::from_selection(selection)),
        )
    }

    pub(super) fn with_authority(
        selection: &'selection SelectedResolutionMountInventory<'store>,
        authority: Rc<SelectedResolutionAuthority<'selection>>,
    ) -> Self {
        Self {
            selection,
            implicit_environment: None,
            implicit_language_version: None,
            authority,
            context_identities: crate::analyzer::resolution::SelectedContextIdentities::new(),
            external_providers: Vec::new(),
            model_authority: None,
            external_models: None,
            go_context_binder: None,
            go_owner_proofs: Default::default(),
            external_signatures: Default::default(),
            namespace_classifiers: selection
                .namespace_definition_providers()
                .iter()
                .map(|(language, _, provider)| (language.clone(), provider()))
                .collect(),
        }
    }

    /// A dormant caller supplies its exact selected environment publication.
    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn with_implicit_environment(
        mut self,
        environment: i64,
        declared_version: Option<(u16, u16)>,
    ) -> Self {
        self.implicit_environment = Some(environment);
        self.implicit_language_version = declared_version;
        self
    }

    fn intrinsic_entry(
        &self,
        identity: SemanticId,
    ) -> Option<crate::analyzer::resolution::universe::UniverseEntry> {
        let digest = self
            .selection
            .shared_names()
            .digest_for_id(identity.shared_name_id()?)?;
        crate::analyzer::resolution::universe::entry_for_digest(digest)
    }

    pub(super) fn with_external_models(
        mut self,
        models: Option<
            std::sync::Arc<crate::analyzer::semantic_model::ResolvedActiveSemanticModels>,
        >,
    ) -> Self {
        self.external_models = models;
        self
    }

    pub(super) fn with_model_authority(
        mut self,
        authority: Option<
            std::sync::Arc<dyn super::resolution_operation::SelectedModelAuthority + Send + Sync>,
        >,
    ) -> Self {
        self.model_authority = authority;
        self
    }

    /// Construct query-local external owner coordinates for cross-crate tests.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn with_external_owner_test_inventory(
        self,
        providers: Vec<String>,
        owners: &[crate::analyzer::resolution::ExternalOwnerIdentity],
    ) -> (Self, Vec<SemanticId>) {
        let identities = crate::analyzer::resolution::SelectedContextIdentities::new();
        let definitions = owners
            .iter()
            .map(|owner| identities.external_owner_semantic(owner, &self.selection.shared_names()))
            .collect();
        (
            self.with_context_identities(identities)
                .with_external_providers(providers),
            definitions,
        )
    }

    pub(super) fn with_external_providers(mut self, providers: Vec<String>) -> Self {
        self.external_providers = providers;
        self
    }

    pub(super) fn with_go_context_binder(
        mut self,
        binder: &'selection dyn GoDefinitionContextBinder,
    ) -> Self {
        self.go_context_binder = Some(binder);
        self
    }

    pub(super) fn with_context_identities(
        mut self,
        identities: crate::analyzer::resolution::SelectedContextIdentities,
    ) -> Self {
        self.context_identities = identities;
        self
    }

    /// Read a positioned named-argument label from its exact selected source
    /// site. The call row supplies the callee reference that the resolution
    /// engine must select before the label can name a parameter.
    fn read_named_argument_label_for_reference(
        &self,
        reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<NamedArgumentLabelRead> {
        if cancellation.is_cancelled() || !self.validate_selected_interiors(cancellation)? {
            return Ok(NamedArgumentLabelRead::Cancelled);
        }
        assert!(
            reference.shared_name_id().is_none(),
            "positioned named-argument labels have fragment-local reference identities"
        );
        let Some(coordinates) = self.semantic_coordinates(
            &[reference],
            TypedFactRelation::CallApplicabilityCalleeReference,
            cancellation,
        )?
        else {
            return Ok(NamedArgumentLabelRead::Cancelled);
        };
        if cancellation.is_cancelled() {
            return Ok(NamedArgumentLabelRead::Cancelled);
        }
        let Some(coordinate) = coordinates.first().copied() else {
            return Ok(NamedArgumentLabelRead::Missing);
        };
        assert_eq!(
            coordinates.len(),
            1,
            "a positioned label belongs to one mount"
        );
        assert_eq!(coordinate.space, RequestKeySpace::Local);
        let mount = self.mount(coordinate.mount)?;
        let reference_site = coordinate.keys[0];
        let Some(found) = self.read_statement(cancellation, |conn| {
            let mut statement = conn.prepare_cached(
                "SELECT call_site, label FROM main.resolution_named_argument_labels \
                 WHERE blob_id=?1 AND reference_site=?2",
            )?;
            let row = statement
                .query_row([mount.blob_id(), reference_site], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .optional()?;
            Ok(Some(row))
        })?
        else {
            return Ok(NamedArgumentLabelRead::Cancelled);
        };
        let Some((call_site, spelling)) = found else {
            return Ok(NamedArgumentLabelRead::Missing);
        };
        let call_site = u32::try_from(call_site).map_err(|_| {
            invalid_fact(format!("named-argument call site is invalid: {call_site}"))
        })?;
        let call_site =
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId::new(call_site);
        let call_identity =
            crate::analyzer::resolution::call_semantic_identity(call_site).fragment_local_digest();
        let Some(callee_sites) = self.read_statement(cancellation, |conn| {
            let mut statement = conn.prepare_cached(
                "SELECT obligation.callee_reference \
                 FROM main.resolution_semantic_catalog AS call_identity \
                 JOIN main.resolution_call_obligations AS obligation \
                   ON obligation.blob_id=call_identity.blob_id \
                  AND obligation.call=call_identity.local_key \
                 WHERE call_identity.blob_id=?1 AND call_identity.identity_digest=?2 \
                 ORDER BY obligation.callee_reference LIMIT 2",
            )?;
            let mut rows =
                statement.query(rusqlite::params![mount.blob_id(), call_identity.as_slice()])?;
            let mut sites = Vec::new();
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let site = nonnegative_i64(row, 0, "named-argument callee site")?;
                sites.push(u32::try_from(site).map_err(|_| {
                    invalid_fact(format!("named-argument callee site is invalid: {site}"))
                })?);
            }
            Ok(Some(sites))
        })?
        else {
            return Ok(NamedArgumentLabelRead::Cancelled);
        };
        if callee_sites.len() > 1 {
            return Err(invalid_fact(format!(
                "named-argument call site has multiple callee references: {call_site:?}"
            )));
        }
        let callee_reference = callee_sites.first().copied().map(|site| {
            crate::analyzer::resolution::mounted_site_semantic(
                mount.fragment_id(),
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId::new(site),
            )
        });
        Ok(NamedArgumentLabelRead::Found(NamedArgumentLabel {
            call: crate::analyzer::resolution::mounted_site_semantic(
                mount.fragment_id(),
                call_site,
            ),
            callee_reference,
            spelling,
        }))
    }

    /// Resolve a label only within the exact selected callable's parameter
    /// rows. Multiple matches are not guessed; the caller reports the label
    /// as incomplete.
    fn read_callable_parameter_for_label(
        &self,
        callable: SemanticId,
        label: &str,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<SemanticId>> {
        if cancellation.is_cancelled() || !self.validate_selected_interiors(cancellation)? {
            return Ok(None);
        }
        assert!(
            callable.shared_name_id().is_none(),
            "a selected callable declaration has a fragment-local identity"
        );
        let Some(coordinates) = self.semantic_coordinates(
            &[callable],
            TypedFactRelation::CallableSignatureDefinition,
            cancellation,
        )?
        else {
            return Ok(None);
        };
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let mut matches = Vec::new();
        for coordinate in coordinates {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            assert_eq!(coordinate.request_ordinal, 0);
            assert_eq!(coordinate.space, RequestKeySpace::Local);
            let mount = self.mount(coordinate.mount)?;
            let callable_site = coordinate.keys[0];
            let Some(mut parameter_sites) = self.read_statement(cancellation, |conn| {
                let mut statement = conn.prepare_cached(
                    "SELECT parameter_site FROM main.resolution_callable_parameter_semantics \
                     WHERE blob_id=?1 AND callable_site=?2 AND label=?3 \
                     ORDER BY list_ordinal, ordinal LIMIT 2",
                )?;
                let mut rows =
                    statement.query(rusqlite::params![mount.blob_id(), callable_site, label])?;
                let mut sites = Vec::new();
                while let Some(row) = rows.next()? {
                    if cancellation.is_cancelled() {
                        return Ok(None);
                    }
                    let site = nonnegative_i64(row, 0, "callable parameter site")?;
                    sites.push(u32::try_from(site).map_err(|_| {
                        invalid_fact(format!("callable parameter site is invalid: {site}"))
                    })?);
                }
                Ok(Some(sites))
            })?
            else {
                return Ok(None);
            };
            matches.extend(parameter_sites.drain(..).map(|site| {
                crate::analyzer::resolution::mounted_site_semantic(
                    mount.fragment_id(),
                    brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId::new(site),
                )
            }));
            if matches.len() > 1 {
                return Ok(None);
            }
        }
        Ok((matches.len() == 1).then_some(matches[0]))
    }

    /// The mounts whose authority can answer a request of this relation keyed
    /// on these semantics.
    ///
    /// `relation` is the question, not a mode: each read asks a different one
    /// of the same `(blob_id, identity_id)` shape, and answering any of them
    /// from "which blobs mention this name" opens every blob in the workspace
    /// that spells the name.
    fn interior_mounts_for_semantics(
        &self,
        semantics: &[SemanticId],
        relation: TypedFactRelation,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<SelectedResolutionMountOrdinal>>> {
        let Some(coordinates) = self.semantic_coordinates(semantics, relation, cancellation)?
        else {
            return Ok(None);
        };
        Ok(Some(
            coordinates
                .into_iter()
                .map(|coordinate| coordinate.mount)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        ))
    }

    /// The mounts that hold any qualified route at all, inside the request's
    /// scope.
    ///
    /// The route inventory has no lookup to key on: an endpoint with an open
    /// tail and no fixed first symbol has to look at every route there is.
    /// What it does not have to do is open every blob. The route-lookup
    /// relation read with no identity predicate is exactly the question
    /// "which blobs hold a route", and it is exact because a route lookup is
    /// always a shared name recipe, which the writer asserts, so a blob with a
    /// route always has a row. `(blob_id, relation)` is a primary-key prefix.
    ///
    /// This is one of the two reads that can name a blob other than the one
    /// owning the requested identity, so it is one of the two that the request
    /// scope has to bound: with no identity predicate at all it would
    /// otherwise return every selected mount holding a route, dependents
    /// included, and a forward request in crate A can bind in nothing but A's
    /// dependency closure.
    fn interior_mounts_holding_a_qualified_route(
        &self,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<SelectedResolutionMountOrdinal>>> {
        self.read_statement(cancellation, |conn| {
            let mut statement = conn.prepare_cached(QUALIFIED_ROUTE_MOUNTS_SQL)?;
            let mut rows = statement.query([TypedFactRelation::QualifiedRouteLookup.code()])?;
            let mut mounts = Vec::new();
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                mounts.push(mount_ordinal(row, 0, "qualified route inventory mount")?);
            }
            Ok(Some(mounts))
        })
    }

    /// Read metadata for the requested persisted mount.
    fn mount(
        &self,
        ordinal: SelectedResolutionMountOrdinal,
    ) -> StoreResult<std::sync::Arc<SelectedResolutionMountRecord>> {
        require_selected_mount_record(
            self.selection.persisted_mount_record(ordinal)?,
            ordinal,
            "typed",
        )
    }

    fn read_statement<T>(
        &self,
        cancellation: &CancellationToken,
        job: impl FnOnce(&Connection) -> StoreResult<Option<T>>,
    ) -> StoreResult<Option<T>> {
        read_resolution_statement(self.selection.connection(), cancellation, job)
    }

    fn empty_outcome(&self, cancellation: &CancellationToken) -> StoreResult<TypedFactReadOutcome> {
        if cancellation.is_cancelled() || !self.validate_selected_interiors(cancellation)? {
            return Ok(TypedFactReadOutcome::cancelled(
                ResolutionCompletion::Complete,
            ));
        }
        Ok(if cancellation.is_cancelled() {
            TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete)
        } else {
            TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn validate_selected_interiors_for_test(
        &self,
        cancellation: &CancellationToken,
    ) -> StoreResult<bool> {
        self.validate_selected_interiors(cancellation)
    }

    fn validate_selected_interiors(&self, cancellation: &CancellationToken) -> StoreResult<bool> {
        let Some(stamp) = self.read_statement(cancellation, |_conn| {
            Ok(Some(self.selection.interior_validation_stamp()?))
        })?
        else {
            return Ok(false);
        };
        let certificate = &self.selection.retained().interior_certificates.typed;
        if stamp.is_some() && certificate.get() == stamp {
            return Ok(!cancellation.is_cancelled());
        }
        let expected = self.selection.persisted_mount_count();
        // One aggregate read, as the lexical source's sentinel does: a loop that
        // decoded each mount record would make every typed read cost one
        // statement per workspace file.
        let Some((mounted, with_interior)) = self.read_statement(cancellation, |conn| {
            let mut statement = conn.prepare_cached(
                r#"SELECT COUNT(*), COUNT(interior.blob_id)
                   FROM temp.selected_resolution_mounts AS m
                   LEFT JOIN main.resolution_fragment_interiors AS interior
                     ON interior.blob_id = m.blob_id
                    AND interior.lang = m.storage_language
                    AND interior.semantic_language = m.semantic_language
                    AND interior.producer_epoch = m.producer_epoch
                    AND interior.interior_digest = m.interior_digest
                    AND interior.publication_state = 'complete'
                    AND EXISTS (
                      SELECT 1 FROM main.source_fact_readiness AS visibility
                      WHERE visibility.blob_id = m.blob_id AND visibility.available = 1
                    )"#,
            )?;
            let counts = statement
                .query_row([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
            Ok(Some(counts))
        })?
        else {
            return Ok(false);
        };
        if with_interior != mounted {
            return Err(invalid_fact(format!(
                "{} of {mounted} selected typed mounts lost their exact complete interior",
                mounted - with_interior
            )));
        }
        let mounted = usize::try_from(mounted).expect("selected mount count fits usize");
        if mounted != expected {
            return Err(invalid_fact(format!(
                "selected typed sentinel expected {expected} mounts, decoded {mounted}"
            )));
        }
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        // Keep the pre-scan stamp: a concurrent commit during validation must
        // cause the next boundary to rescan, not inherit a newer valid stamp.
        certificate.set(stamp);
        Ok(true)
    }

    /// `relation` is what a workspace-shared request resolves its mounts
    /// through: the rows of the one tier 1 family under an interned identity
    /// and that relation. Which relation is the question being asked, not a
    /// mode: see [`TypedFactRelation`].
    fn semantic_coordinates(
        &self,
        identities: &[SemanticId],
        relation: TypedFactRelation,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<RequestCoordinate>>> {
        if identities.is_empty() {
            return Ok(Some(Vec::new()));
        }
        let mut direct = Vec::new();
        let mut shared = Vec::new();
        let names = self
            .selection
            .shared_name_table()
            .interner(self.selection.connection());
        for (request_ordinal, &identity) in identities.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            if matches!(
                relation,
                TypedFactRelation::QualifiedRouteGapReason
                    | TypedFactRelation::CallApplicabilityGapReason
                    | TypedFactRelation::GapReasonProvenanceReason
                    | TypedFactRelation::DefinitionPropertyGapReason
            ) {
                // Completion reasons can name shared semantics (for example,
                // an unproven external member binding). They have no persisted
                // gap provenance or obligations in any of these relations.
                if identity.shared_name_id().is_some() {
                    continue;
                }
                // A gap reason has no catalog row, so no digest can classify
                // it: its key range does. An ordinary reason needs its blob
                // key here; a stage reason keeps its full runtime id and is
                // answered by the stage SQL.
                if let Some((mount, key)) = self.authority.ordinary_gap_reason(identity)? {
                    direct.push(RequestCoordinate::new(
                        request_ordinal,
                        mount,
                        i64::from(key),
                    ));
                }
                continue;
            }
            let provenance = if let Some(name) = identity.shared_name_id() {
                Some(SelectedSemanticProvenance::Shared(
                    crate::analyzer::resolution::ResolutionSemanticIdentity::shared(name),
                ))
            } else {
                let Some(provenance) = self
                    .authority
                    .semantic_catalog_provenance(identity, cancellation)?
                else {
                    return Ok(None);
                };
                provenance
            };
            match provenance {
                Some(SelectedSemanticProvenance::FragmentLocal(local)) => {
                    direct.push(RequestCoordinate::new(
                        request_ordinal,
                        local.mount().ordinal(),
                        local.local_key().get(),
                    ));
                }
                // Only the ordinary arm needs blob keys. The stage arm keeps
                // the original full runtime ID and queries its SQL authority.
                Some(SelectedSemanticProvenance::Stage(_)) => {}
                Some(SelectedSemanticProvenance::Shared(name)) => {
                    let Some(name) = name.shared_name() else {
                        panic!("a shared semantic provenance carries a shared name")
                    };
                    if let Some(stored) = names.to_persisted(name) {
                        shared.push((request_ordinal, stored));
                    }
                }
                None => {}
            }
        }
        if !shared.is_empty() {
            assert!(
                !matches!(
                    relation,
                    TypedFactRelation::RustReferenceContext
                        | TypedFactRelation::RustDeclarationAuthority
                ),
                "{relation:?} has no membership writer in prepare_typed_fact_lookups, \
                 so a shared key for it would name no mount and answer nothing silently"
            );
            let sql = shared_membership_sql(shared.len(), relation);
            let mut parameters = Vec::with_capacity(shared.len() * 2);
            for (ordinal, name) in &shared {
                parameters.push(Value::Integer(
                    i64::try_from(*ordinal).expect("request ordinal fits i64"),
                ));
                parameters.push(Value::Integer(i64::from(name.get())));
            }
            let Some(rows) = self.read_statement(cancellation, |conn| {
                let mut statement = conn.prepare_cached(&sql)?;
                let mut rows = statement.query(params_from_iter(parameters.iter()))?;
                let mut decoded = Vec::new();
                while let Some(row) = rows.next()? {
                    if cancellation.is_cancelled() {
                        return Ok(None);
                    }
                    decoded.push(RequestCoordinate::shared(
                        usize_from_nonnegative(row, 0, "shared request ordinal")?,
                        mount_ordinal(row, 1, "shared semantic mount")?,
                        nonnegative_i64(row, 2, "shared semantic key")?,
                    ));
                }
                Ok(Some(decoded))
            })?
            else {
                return Ok(None);
            };
            #[cfg(any(test, feature = "test-support"))]
            shared_request_probe::observe(
                relation,
                shared.len(),
                rows.iter()
                    .map(|coordinate| coordinate.mount)
                    .collect::<BTreeSet<_>>()
                    .len(),
            );
            direct.extend(rows);
        }
        direct.sort_unstable();
        direct.dedup();
        Ok(Some(direct))
    }

    fn node_coordinates(
        &self,
        identities: &[BindingNodeId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<RequestCoordinate>>> {
        let mut coordinates = Vec::with_capacity(identities.len());
        for (request_ordinal, &identity) in identities.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let Some(provenance) = self
                .authority
                .node_catalog_provenance(identity, cancellation)?
            else {
                return Ok(None);
            };
            if provenance.is_none()
                && !(self
                    .selection
                    .stage_family_is_globally_empty(super::resolution_stage::StageFamily::Nodes)?
                    && self.selection.stage_family_is_globally_empty(
                        super::resolution_stage::StageFamily::NodeCoordinates,
                    )?)
            {
                let Some(registered) = self.read_statement(cancellation, |connection| {
                    Ok(Some(connection.prepare_cached(
                        "SELECT EXISTS(SELECT 1 FROM temp.selected_resolution_stage_nodes WHERE node=?1) \
                         OR EXISTS(SELECT 1 FROM temp.selected_resolution_stage_node_coordinates WHERE runtime_key=?1)",
                    )?.query_row([super::resolution_stage::codec::encode_node(identity)], |row| row.get::<_, bool>(0))?))
                })? else {
                    return Ok(None);
                };
                if registered {
                    // Authority is request-wide; the stage result query applies
                    // the current scope. Catalog-only nodes remain valid too.
                    continue;
                }
            }
            match provenance {
                Some(SelectedNodeProvenance::FragmentLocal(local)) => {
                    coordinates.push(RequestCoordinate::new(
                        request_ordinal,
                        local.mount().ordinal(),
                        local.local_key().get(),
                    ))
                }
                Some(SelectedNodeProvenance::Stage(_)) => {}
                Some(SelectedNodeProvenance::UniversalRoot) => {
                    return Err(invalid_fact(
                        "universal root is not a persisted typed node request",
                    ));
                }
                Some(SelectedNodeProvenance::ContextBoundary) => {
                    return Err(invalid_fact(
                        "Java placement boundary is not a persisted typed node request",
                    ));
                }
                None => {
                    return Err(invalid_fact(format!(
                        "typed request node {identity} has no selected identity provenance"
                    )));
                }
            }
        }
        coordinates.sort_unstable();
        coordinates.dedup();
        Ok(Some(coordinates))
    }
}

/// Which identity space a resolved request key lives in.
///
/// A typed column holds one space and only one (the draft's section 1), and
/// the two spaces number independently: a blob-local catalog position 7 and
/// `resolution_identities.id` 7 are different things. A reader that bound a
/// shared id against a local column would match an unrelated row, so the space
/// travels with the key and each statement takes the keys of its own column's
/// space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RequestKeySpace {
    /// A blob's own catalog position.
    Local,
    /// A `resolution_identities.id`.
    Shared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct RequestCoordinate {
    request_ordinal: usize,
    mount: SelectedResolutionMountOrdinal,
    space: RequestKeySpace,
    keys: [i64; 2],
}

impl RequestCoordinate {
    const fn new(request_ordinal: usize, mount: SelectedResolutionMountOrdinal, key: i64) -> Self {
        Self {
            request_ordinal,
            mount,
            space: RequestKeySpace::Local,
            keys: [key, -1],
        }
    }

    const fn shared(
        request_ordinal: usize,
        mount: SelectedResolutionMountOrdinal,
        identity: i64,
    ) -> Self {
        Self {
            request_ordinal,
            mount,
            space: RequestKeySpace::Shared,
            keys: [identity, -1],
        }
    }
}

/// The mounts a workspace-shared typed request names, for `requests`
/// `(request_ordinal, identity_id)` pairs bound in that order.
///
/// Tier 1 keeps the shared slice of the term catalog as `(blob_id,
/// identity_id)` relations, so a shared request names its mounts without
/// opening any blob. Every join is inner: the statement returns one row per
/// mount that the relation actually names, not one row per request per
/// selected mount. A selected mount that lost its exact complete interior
/// drops out here and is reported by `validate_selected_interiors`, which
/// asserts that condition over the whole selection on its own.
///
/// This is the one read that can first put a blob other than the requested
/// identity's owner into a batch, so it is where the request scope belongs:
/// the membership predicate is `(relation, identity_id)` and nothing else, and
/// without the scope join it names every selected blob that holds the relation
/// under that name, dependents of the staged crate included. A reference in
/// crate A can bind only inside A's dependency closure, so those mounts cannot
/// contribute an answer and only cost unnecessary authority reads.
///
/// The mount is found by its blob. Without `INDEXED BY` the planner reached
/// it through the unique `(storage_language, persisted_relative_path)` index
/// with only the language bound, walking every Rust mount for every
/// membership row: on tract (1,027 mounts, 309 rows for the callable `name`)
/// that was about 96 ms a read, 522 reads and 50 s of one usage scan (#3761),
/// against about 1.5 ms through the blob index. `ANALYZE` with the bounded
/// analysis limit the store uses keeps the slow plan, so the plan is fixed
/// here rather than left to statistics.
pub(super) fn shared_membership_sql(requests: usize, relation: TypedFactRelation) -> String {
    let values = values_sql(requests, 2);
    format!(
        r#"WITH requested(request_ordinal, identity_id) AS (VALUES {values})
           SELECT r.request_ordinal, m.mount_ordinal, membership.identity_id
           FROM requested AS r
           CROSS JOIN main.{TYPED_FACT_LOOKUP_FAMILY} AS membership
             ON membership.relation = {relation}
            AND membership.identity_id = r.identity_id
           CROSS JOIN temp.selected_resolution_mounts AS m
                INDEXED BY selected_resolution_mounts_blob_ordinal
             ON m.blob_id = membership.blob_id
           CROSS JOIN temp.selected_resolution_scope_mounts AS scope
             ON scope.mount_ordinal = m.mount_ordinal
           CROSS JOIN main.resolution_fragment_interiors AS interior
             ON interior.blob_id = m.blob_id
            AND interior.lang = m.storage_language
            AND interior.semantic_language = m.semantic_language
            AND interior.producer_epoch = m.producer_epoch
            AND interior.interior_digest = m.interior_digest
            AND interior.publication_state = 'complete'
           ORDER BY r.request_ordinal, m.mount_ordinal"#,
        relation = relation.code(),
    )
}

fn values_sql(rows: usize, arity: usize) -> String {
    assert!(rows > 0);
    let mut parameter = 1_usize;
    (0..rows)
        .map(|_| {
            let row = (0..arity)
                .map(|_| {
                    let current = parameter;
                    parameter += 1;
                    format!("?{current}")
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("({row})")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn invalid_fact(message: impl Into<String>) -> StoreError {
    StoreError::new(message)
}

fn usize_from_nonnegative(row: &Row<'_>, index: usize, label: &str) -> StoreResult<usize> {
    usize::try_from(nonnegative_i64(row, index, label)?)
        .map_err(|_| invalid_fact(format!("{label} does not fit usize")))
}

/// Compose one typed read's membership from the generic family.
///
/// The relation is a required argument. There is no default: a read with no
/// relation has no way to name the blobs that hold its facts, and the
/// name-mention relation that used to stand in for one opened every blob in
/// the workspace that spells the requested name.
/// Test-only accounting for what a workspace-shared typed request resolved to.
///
/// A pin that has to prove a read was *entered* with a shared identity and
/// then opened nothing cannot see either fact from outside the operation: the
/// mount set is consumed inside it, and a read that opens nothing looks
/// exactly like a read that never ran. This records both, per relation, in a
/// fixed-size array of counters on the operation's own thread -- the thread
/// that owns the retained connection `semantic_coordinates` reads through.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod shared_request_probe {
    use std::cell::Cell;

    use super::TypedFactRelation;

    thread_local! {
        static REQUESTS: [Cell<usize>; TypedFactRelation::COUNT] =
            const { [const { Cell::new(0) }; TypedFactRelation::COUNT] };
        static MOUNTS: [Cell<usize>; TypedFactRelation::COUNT] =
            const { [const { Cell::new(0) }; TypedFactRelation::COUNT] };
    }

    #[doc(hidden)]
    pub fn reset() {
        REQUESTS.with(|counters| counters.iter().for_each(|counter| counter.set(0)));
        MOUNTS.with(|counters| counters.iter().for_each(|counter| counter.set(0)));
    }

    pub(super) fn observe(relation: TypedFactRelation, requests: usize, mounts: usize) {
        let index = counter_index(relation);
        REQUESTS.with(|counters| counters[index].set(counters[index].get() + requests));
        MOUNTS.with(|counters| counters[index].set(counters[index].get() + mounts));
    }

    /// Every relation that answered a shared request since the last [`reset`],
    /// with its request and mount counts. A pin prints this when it needs to
    /// say which reads a request actually entered.
    #[doc(hidden)]
    pub fn observed_all() -> Vec<(&'static str, usize, usize)> {
        TypedFactRelation::ALL
            .iter()
            .map(|relation| {
                let (requests, mounts) = observed(*relation);
                (relation.label(), requests, mounts)
            })
            .filter(|(_, requests, _)| *requests > 0)
            .collect()
    }

    /// The shared requests this relation answered, and the distinct mounts
    /// they resolved to, since the last [`reset`].
    #[doc(hidden)]
    pub fn observed(relation: TypedFactRelation) -> (usize, usize) {
        let index = counter_index(relation);
        (
            REQUESTS.with(|counters| counters[index].get()),
            MOUNTS.with(|counters| counters[index].get()),
        )
    }

    fn counter_index(relation: TypedFactRelation) -> usize {
        usize::try_from(relation.code()).expect("a relation code is nonnegative")
    }
}

enum RustFragmentCoordinate {
    FragmentLocal((SelectedResolutionMountOrdinal, i64)),
    Cancelled,
    Unplaced,
}

fn rust_fragment_coordinate(
    authority: &SelectedResolutionAuthority<'_>,
    semantic: SemanticId,
    cancellation: &CancellationToken,
) -> StoreResult<RustFragmentCoordinate> {
    let Some(provenance) = authority.semantic_catalog_provenance(semantic, cancellation)? else {
        return Ok(RustFragmentCoordinate::Cancelled);
    };
    let Some(SelectedSemanticProvenance::FragmentLocal(local)) = provenance else {
        return Ok(RustFragmentCoordinate::Unplaced);
    };
    Ok(RustFragmentCoordinate::FragmentLocal((
        local.mount().ordinal(),
        local.local_key().get(),
    )))
}

impl SelectedTypedFactSource for SelectedResolutionTypedSource<'_, '_> {
    fn supports_conditional_type_seeds(&self) -> bool {
        self.selection.has_conditional_type_seeds()
    }

    fn conditional_type_seeds(
        &self,
        slots: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<crate::analyzer::resolution::ConditionalTypeSeed>> {
        if !self.selection.has_conditional_type_seeds() {
            return Ok(Vec::new());
        }
        if !self.validate_selected_interiors(cancellation)? {
            return Ok(Vec::new());
        }
        let mut seeds = Vec::new();
        for &slot in slots {
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            let Some(ordinal) = slot.ordinal() else {
                continue;
            };
            if ordinal as usize >= self.selection.persisted_mount_count() {
                continue;
            }
            let language = self
                .mount(SelectedResolutionMountOrdinal::new(ordinal))?
                .semantic_language();
            if let Some(support) = super::store_language_support(language)
                && let Some(seed) =
                    support.selected_conditional_type_seed(self.selection, slot, cancellation)?
            {
                seeds.push(seed);
            }
        }
        Ok(seeds)
    }

    fn qualified_member_registrations(
        &self,
    ) -> &'static [crate::analyzer::resolution::fact_source::QualifiedMemberRegistration] {
        if self.selection.has_registered_member_semantics() {
            super::language_support::qualified_member_registrations()
        } else {
            &[]
        }
    }

    fn implicit_base_inputs(
        &self,
        owner: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<crate::analyzer::resolution::ImplicitBaseInputs>> {
        let Some(environment) = self.implicit_environment else {
            return Ok(None);
        };
        if !self.validate_selected_interiors(cancellation)? {
            return Ok(None);
        }
        let language = if let Some(ordinal) = owner.ordinal() {
            self.mount(SelectedResolutionMountOrdinal::new(ordinal))?
                .semantic_language()
        } else if let Some(entry) = self.intrinsic_entry(owner) {
            entry.language
        } else {
            return Ok(None);
        };
        let Some(support) = super::store_language_support(language) else {
            return Ok(None);
        };
        support.selected_implicit_base_inputs(
            self.selection,
            environment,
            self.implicit_language_version,
            owner,
            cancellation,
        )
    }

    fn intrinsic_member_inventory(
        &self,
        owner: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<crate::analyzer::resolution::universe::IntrinsicMemberInventory>> {
        if self.implicit_environment.is_none() || cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(entry) = self.intrinsic_entry(owner) else {
            return Ok(None);
        };
        // A foreign intrinsic owner cannot borrow this language's versioned
        // authority. JVM owners retain their selected declaration check.
        if !crate::analyzer::resolution::universe::requires_selected_scope(entry.language) {
            return Ok(None);
        }
        Ok(
            crate::analyzer::resolution::universe::closed_intrinsic_member_inventory(
                entry.identity_spelling,
                self.implicit_language_version,
            ),
        )
    }

    fn jvm_intrinsic_owner_is_unshadowed(
        &self,
        owner_fqn: &str,
        cancellation: &CancellationToken,
    ) -> StoreResult<bool> {
        Ok(self
            .read_statement(cancellation, |connection| {
                Ok(Some(
                    super::resolution_operation::selected_jvm_declaration_owner(
                        super::resolution_operation::nominal_rules::jvm_external_owner_relations(),
                        connection,
                        self.model_authority.as_deref(),
                        &self.external_providers,
                        owner_fqn,
                    )?
                    .is_none(),
                ))
            })?
            .unwrap_or(false))
    }

    fn generated_items_cannot_shadow_bindings(
        &self,
        reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<bool> {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let Some(ordinal) = reference.ordinal() else {
            return Ok(false);
        };
        Ok(crate::analyzer::semantic::languages::language_knowledge(
            self.mount(SelectedResolutionMountOrdinal::new(ordinal))?
                .semantic_language(),
        )
        .is_some_and(|support| support.generated_items_cannot_shadow_bindings()))
    }

    fn named_argument_label_for_reference(
        &self,
        reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<NamedArgumentLabelRead> {
        self.read_named_argument_label_for_reference(reference, cancellation)
    }

    fn callable_parameter_for_label(
        &self,
        callable: SemanticId,
        label: &str,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<SemanticId>> {
        self.read_callable_parameter_for_label(callable, label, cancellation)
    }

    fn lookup_namespace(
        &self,
        lookup: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace>>
    {
        let names = self
            .selection
            .shared_name_table()
            .interner(self.selection.connection());
        let Some(name) = lookup
            .shared_name_id()
            .and_then(|name| names.to_persisted(name))
        else {
            return Ok(None);
        };
        let result = self.read_statement(cancellation, |_conn| {
            Ok(
                super::resolution_prepare::resolution_rows::read_stored_lookup_recipes(
                    self.selection,
                    &[i64::from(name.get())],
                    cancellation,
                )?
                .map(|recipes| {
                    recipes
                        .get(&i64::from(name.get()))
                        .map(|recipe| recipe.namespace())
                }),
            )
        })?;
        Ok(result.flatten())
    }

    fn selection_has_java_semantics(&self) -> bool {
        self.selection.has_java_semantics()
    }

    fn selection_has_jvm_semantics(&self) -> bool {
        self.selection.has_jvm_semantics()
    }

    fn external_callable_result_type_identities(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(SemanticId, SemanticId)>>> {
        SelectedResolutionTypedSource::external_callable_result_type_identities(
            self,
            definitions,
            cancellation,
        )
    }

    fn fragment_call_target_precedence(
        &self,
        fragment: BindingFragmentId,
        namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
        ordinal: u32,
    ) -> StoreResult<u32> {
        let language = self.fragment_language(fragment)?;
        Ok(
            crate::analyzer::semantic::languages::language_knowledge(language)
                .and_then(|support| support.call_target_lookup_routes())
                .and_then(|routes| routes.iter().find(|(_, candidate)| *candidate == namespace))
                .map_or(ordinal, |(rank, _)| *rank),
        )
    }

    fn fragment_language(&self, fragment: BindingFragmentId) -> StoreResult<Language> {
        let Some(ordinal) = self.selection.mount_ordinal_for_fragment(fragment) else {
            return Ok(Language::None);
        };
        Ok(self
            .selection
            .mount_record_by_ordinal(ordinal)?
            .semantic_language())
    }

    fn fragment_type_qualifiers_search_companion_members(
        &self,
        fragment: BindingFragmentId,
    ) -> StoreResult<bool> {
        let Some(ordinal) = self.selection.mount_ordinal_for_fragment(fragment) else {
            return Ok(false);
        };
        let record = self.selection.mount_record_by_ordinal(ordinal)?;
        Ok(language_type_qualifiers_search_companion_members(
            record.semantic_language(),
        ))
    }

    fn intrinsic_reverse_index_uses_shared_type_names(&self) -> bool {
        true
    }

    fn qualify_selection_path(
        &self,
        reference: SemanticId,
        path: &mut crate::analyzer::resolution::PartialPath,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<bool>> {
        super::resolution_operation::rust_crate_access::qualify_import_path(
            self.selection,
            reference,
            path,
            cancellation,
        )
    }

    fn rust_crate_access(
        &self,
        crate_key: [u8; 32],
        base_blobs: &[(BindingFragmentId, i64)],
        reference: Option<&SelectedTypedRow<LoweredRustReferenceContext>>,
        definition: Option<&SelectedTypedRow<LoweredRustDeclarationAuthority>>,
    ) -> StoreResult<Option<crate::analyzer::resolution::DeclarationAccessDecision>> {
        super::resolution_operation::rust_crate_access::access(
            self.selection,
            crate_key,
            base_blobs,
            reference,
            definition,
        )
    }

    /// The crate-set visibility decision for one `pub(crate)` route.
    ///
    /// This reads the tier-1 crate rows, not the resolution interior, so it
    /// belongs on the selected typed source whatever the interior serves. The
    /// trait default answers `None`, which is "no decision" and silently
    /// admits a private route, so this override is not optional.
    fn rust_crate_set_access(
        &self,
        crate_key: [u8; 32],
        base_blobs: &[(BindingFragmentId, i64)],
        reference: Option<&SelectedTypedRow<LoweredRustReferenceContext>>,
        definition: Option<&SelectedTypedRow<LoweredRustDeclarationAuthority>>,
    ) -> StoreResult<Option<crate::analyzer::resolution::DeclarationAccessDecision>> {
        super::resolution_operation::rust_crate_access::set_access(
            self.selection,
            crate_key,
            base_blobs,
            reference,
            definition,
        )
    }

    /// Only an ordinary selected declaration can name persisted impl rows.
    /// Resolved trait endpoints name workspace declarations, so they cannot
    /// establish the standard-library Deref identity and are excluded here.
    fn rust_receiver_impl_targets(
        &self,
        owner: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<SemanticId>> {
        let (ordinal, key) = match rust_fragment_coordinate(&self.authority, owner, cancellation)? {
            RustFragmentCoordinate::FragmentLocal(coordinate) => coordinate,
            RustFragmentCoordinate::Cancelled | RustFragmentCoordinate::Unplaced => {
                return Ok(Vec::new());
            }
        };
        // One indexed statement for the common empty case. The target lookup is
        // an identifier value selected through the impl's structured children.

        let coordinates = self
            .selection
            .connection()
            .prepare_cached(RUST_RECEIVER_IMPL_TARGETS_SQL)?
            .query_map(rusqlite::params![ordinal.get(), key], |row| {
                Ok((row.get::<_, u32>(0)?, row.get::<_, u32>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut result = Vec::with_capacity(coordinates.len());
        for (ordinal, key) in coordinates {
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            let mount = self
                .selection
                .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
            result.push(crate::analyzer::resolution::mounted_site_semantic(
                mount.fragment_id(),
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId::new(key),
            ));
        }
        Ok(result)
    }

    /// Asked of the tier-1 crate rows, like the two access decisions above,
    /// so it belongs on the selected typed source whatever the interior
    /// serves. Only ordinary provenance has persisted crate rows: an owner or
    /// a reference that is staged content is `Unplaced`, never an empty set.
    fn rust_implemented_traits_nameable_at(
        &self,
        owner: SemanticId,
        reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<RustImplementedTraits> {
        // A type identity that belongs to no file is an intrinsic or a shared
        // name: nothing in the workspace declares it, so no crate row binds it.
        if owner.ordinal().is_none() {
            return Ok(RustImplementedTraits::Traits(Vec::new()));
        }
        let reference_mount = SelectedResolutionMountOrdinal::new(
            reference
                .ordinal()
                .expect("a qualified member reference is written in a selected file"),
        );
        if self
            .selection
            .mount_record_by_ordinal(reference_mount)?
            .semantic_language()
            != Language::Rust
        {
            return Ok(RustImplementedTraits::Traits(Vec::new()));
        }
        let owner = match rust_fragment_coordinate(&self.authority, owner, cancellation)? {
            RustFragmentCoordinate::FragmentLocal(coordinate) => coordinate,
            RustFragmentCoordinate::Cancelled => return Ok(RustImplementedTraits::Cancelled),
            RustFragmentCoordinate::Unplaced => return Ok(RustImplementedTraits::Unplaced),
        };
        let reference = match rust_fragment_coordinate(&self.authority, reference, cancellation)? {
            RustFragmentCoordinate::FragmentLocal(coordinate) => coordinate,
            RustFragmentCoordinate::Cancelled => return Ok(RustImplementedTraits::Cancelled),
            RustFragmentCoordinate::Unplaced => return Ok(RustImplementedTraits::Unplaced),
        };
        super::resolution_operation::rust_crate_rows::implemented_traits_nameable_at(
            self.selection,
            owner,
            reference,
            cancellation,
        )
    }

    /// Whether the reference can name this specific Rust trait, independent of its implementor.
    fn rust_trait_nameable_at(
        &self,
        owner: SemanticId,
        reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<RustImplementedTraits> {
        // A type identity that belongs to no file is an intrinsic or a shared
        // name: nothing in the workspace declares it, so no crate row binds it.
        if owner.ordinal().is_none() {
            return Ok(RustImplementedTraits::Traits(Vec::new()));
        }
        let reference_mount = SelectedResolutionMountOrdinal::new(
            reference
                .ordinal()
                .expect("a qualified member reference is written in a selected file"),
        );
        if self
            .selection
            .mount_record_by_ordinal(reference_mount)?
            .semantic_language()
            != Language::Rust
        {
            return Ok(RustImplementedTraits::Traits(Vec::new()));
        }
        let owner = match rust_fragment_coordinate(&self.authority, owner, cancellation)? {
            RustFragmentCoordinate::FragmentLocal(coordinate) => coordinate,
            RustFragmentCoordinate::Cancelled => return Ok(RustImplementedTraits::Cancelled),
            RustFragmentCoordinate::Unplaced => return Ok(RustImplementedTraits::Unplaced),
        };
        let reference = match rust_fragment_coordinate(&self.authority, reference, cancellation)? {
            RustFragmentCoordinate::FragmentLocal(coordinate) => coordinate,
            RustFragmentCoordinate::Cancelled => return Ok(RustImplementedTraits::Cancelled),
            RustFragmentCoordinate::Unplaced => return Ok(RustImplementedTraits::Unplaced),
        };
        super::resolution_operation::rust_crate_rows::trait_nameable_at(
            self.selection,
            owner,
            reference,
            cancellation,
        )
    }

    /// Asked of the tier-1 crate rows like the question above. A member that
    /// is staged content or belongs to no file has no persisted impl row, so
    /// its header is resolved instead.
    fn rust_impl_item_traits(
        &self,
        member: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<RustImplementedTraits> {
        let Some(ordinal) = member.ordinal() else {
            return Ok(RustImplementedTraits::Unplaced);
        };
        if self
            .selection
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?
            .semantic_language()
            != Language::Rust
        {
            return Ok(RustImplementedTraits::Traits(Vec::new()));
        }
        let coordinate = match rust_fragment_coordinate(&self.authority, member, cancellation)? {
            RustFragmentCoordinate::FragmentLocal(coordinate) => coordinate,
            RustFragmentCoordinate::Cancelled => return Ok(RustImplementedTraits::Cancelled),
            RustFragmentCoordinate::Unplaced => return Ok(RustImplementedTraits::Unplaced),
        };
        super::resolution_operation::rust_crate_rows::impl_item_traits(
            self.selection,
            coordinate,
            cancellation,
        )
    }

    fn java_access_endpoints(
        &self,
        semantics: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<crate::analyzer::resolution::JavaAccessEndpoint>>> {
        java_access::read(self, semantics, cancellation)
    }

    fn jvm_access_endpoints(
        &self,
        semantics: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<crate::analyzer::resolution::JvmAccessEndpoint>>> {
        java_access::read_jvm(self, semantics, cancellation)
    }

    fn go_callable_lookups(
        &self,
        lookups: &[(BindingFragmentId, SemanticId)],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(SemanticId, SemanticId)>>> {
        use super::resolution_lexical::{
            SelectedLookupRecipeReadOutcome, SelectedLookupRecipeRequest,
            SelectedResolutionLexicalSource,
        };

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
        let lexical = SelectedResolutionLexicalSource::with_authority(
            self.selection,
            Rc::clone(&self.authority),
        );
        let requests = lookups
            .iter()
            .map(|&(fragment, semantic)| SelectedLookupRecipeRequest { fragment, semantic })
            .collect::<Vec<_>>();
        let SelectedLookupRecipeReadOutcome::Ready(recipes) =
            lexical.lookup_semantic_recipes(&requests, cancellation, None)?
        else {
            return Ok(None);
        };
        let names = self
            .selection
            .shared_name_table()
            .interner(self.selection.connection());
        let mut result = Vec::new();
        for ((_, lookup), recipe) in lookups.iter().zip(recipes.iter()) {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let Some(recipe) = recipe else {
                continue;
            };
            if recipe.identity_domain() == language_identity_domain(Language::Go)
                && matches!(
                    recipe.namespace(),
                    ResolutionNamespace::Value | ResolutionNamespace::Callable
                )
            {
                let callable = crate::analyzer::resolution::ResolutionLookupSemanticRecipe::new(
                    Language::Go,
                    ResolutionNamespace::Callable,
                    recipe.spelling(),
                )
                .semantic(&names);
                result.push((*lookup, callable));
            }
        }
        Ok(Some(result))
    }

    fn invocation_roles_for_references(
        &self,
        references: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<crate::analyzer::resolution::SelectedInvocationRole>>> {
        use crate::analyzer::resolution::{SelectedInvocationRole, mounted_site_semantic};
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionInvocationRole;
        let mut coordinates = Vec::new();
        for (ordinal, &reference) in references.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let Some(provenance) = self
                .authority
                .semantic_catalog_provenance(reference, cancellation)?
            else {
                return Ok(None);
            };
            if let Some(SelectedSemanticProvenance::FragmentLocal(local)) = provenance {
                coordinates.push(RequestCoordinate::new(
                    ordinal,
                    local.mount().ordinal(),
                    local.local_key().get(),
                ));
            }
        }
        let mut result = Vec::new();
        for (ordinal, keys) in group_keys(coordinates.into_iter()) {
            let mount = self.mount(ordinal)?;
            let key_array = json_array(keys);
            let Some(rows) = self.read_statement(cancellation, |conn| {
                let mut statement = conn.prepare_cached(INVOCATION_ROLES_FOR_REFERENCES_SQL)?;
                let mut rows = statement.query(rusqlite::params![mount.blob_id(), key_array])?;
                let mut result = Vec::new();
                while let Some(row) = rows.next()? {
                    if cancellation.is_cancelled() {
                        return Ok(None);
                    }
                    let label: String = row.get(1)?;
                    let role = match label.as_str() {
                        "unapply" => ResolutionInvocationRole::Unapply,
                        "unapply_seq" => ResolutionInvocationRole::UnapplySeq,
                        "direct" => ResolutionInvocationRole::Direct,
                        "apply" => ResolutionInvocationRole::Apply,
                        _ => {
                            return Err(StoreError::new(format!(
                                "unknown invocation role {label:?}"
                            )));
                        }
                    };
                    result.push(SelectedInvocationRole {
                        reference: mounted_site_semantic(
                            mount.fragment_id(),
                            brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId::new(
                                row.get(0)?,
                            ),
                        ),
                        language: mount.semantic_language(),
                        role,
                    });
                }
                Ok(Some(result))
            })?
            else {
                return Ok(None);
            };
            result.extend(rows);
        }
        Ok(Some(result))
    }

    fn lookups_outside_implicit_root(
        &self,
        lookups: &[(BindingFragmentId, SemanticId)],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<SemanticId>>> {
        use super::resolution_lexical::{
            SelectedLookupRecipeReadOutcome, SelectedLookupRecipeRequest,
            SelectedResolutionLexicalSource,
        };

        use crate::analyzer::resolution::{
            MAX_SOURCE_ROWS_PER_BATCH, language_has_jvm_semantics, language_identity_domain,
            language_implicit_root_member_names,
        };

        let lexical = SelectedResolutionLexicalSource::with_authority(
            self.selection,
            Rc::clone(&self.authority),
        );
        let mut result = Vec::new();
        for chunk in lookups.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
            let requests = chunk
                .iter()
                .map(|&(fragment, semantic)| SelectedLookupRecipeRequest { fragment, semantic })
                .collect::<Vec<_>>();
            let SelectedLookupRecipeReadOutcome::Ready(recipes) =
                lexical.lookup_semantic_recipes(&requests, cancellation, None)?
            else {
                return Ok(None);
            };
            for ((_, lookup), recipe) in chunk.iter().zip(recipes.iter()) {
                let Some(recipe) = recipe else {
                    continue;
                };
                // Java, Kotlin and Scala share one lookup identity domain, so
                // the recipe names the domain, not the source language. The
                // lookup is outside the implicit root only when no language of
                // its domain has an implicit-root member of that spelling.
                let mut languages = Language::ALL.into_iter().filter(|&language| {
                    language_identity_domain(language) == recipe.identity_domain()
                });
                let spelling = recipe.spelling();
                if languages.clone().any(language_has_jvm_semantics)
                    && languages.all(|language| {
                        !language_implicit_root_member_names(language).contains(&spelling)
                    })
                {
                    result.push(*lookup);
                }
            }
        }
        Ok((!cancellation.is_cancelled()).then_some(result))
    }

    fn generic_parameter_declarations(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<SemanticId>>> {
        // A type-namespace lexical parameter is a generic parameter. Read the
        // existing native bridge instead of making impls synthetic type owners.
        let mut found = Vec::new();
        for chunk in
            definitions.chunks(crate::analyzer::resolution::MAX_TYPED_FACT_REQUESTS_PER_BATCH)
        {
            let mut coordinates = std::collections::BTreeMap::new();
            for &definition in chunk {
                let Some(provenance) = self
                    .authority
                    .semantic_catalog_provenance(definition, cancellation)?
                else {
                    return Ok(None);
                };
                if let Some(SelectedSemanticProvenance::FragmentLocal(local)) = provenance {
                    coordinates.insert(
                        (local.mount().ordinal(), local.local_key().get()),
                        definition,
                    );
                }
            }
            if coordinates.is_empty() {
                continue;
            }
            let requests = json_pair_array(
                coordinates
                    .keys()
                    .map(|(mount, key)| (i64::from(mount.get()), *key)),
            );
            let Some(rows) = self.read_statement(cancellation, |connection| {
                let mut statement =
                    connection.prepare_cached(GENERIC_PARAMETER_DECLARATIONS_SQL)?;
                let mut rows = statement.query([&requests])?;
                let mut result = Vec::new();
                while let Some(row) = rows.next()? {
                    if cancellation.is_cancelled() {
                        return Ok(None);
                    }
                    result.push(
                        coordinates[&(
                            SelectedResolutionMountOrdinal::new(row.get(0)?),
                            row.get::<_, i64>(1)?,
                        )],
                    );
                }
                Ok(Some(result))
            })?
            else {
                return Ok(None);
            };
            found.extend(rows);
        }
        Ok((!cancellation.is_cancelled()).then_some(found))
    }

    fn deferred_member_participation(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<bool>>> {
        Ok(
            go_members::source_participation(self, definitions, cancellation)?.map(|roles| {
                roles
                    .into_iter()
                    .map(|role| role.as_deref() != Some("ignored"))
                    .collect()
            }),
        )
    }

    fn go_package_member_sources(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<Option<Vec<SemanticId>>>>> {
        go_members::package_member_sources(self, definitions, cancellation)
    }

    fn go_source_placement_proofs(
        &self,
        sources: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<bool>>> {
        Ok(
            go_members::source_participation(self, sources, cancellation)?
                .map(|roles| roles.into_iter().map(|role| role.is_some()).collect()),
        )
    }

    fn deferred_member_owner_proofs(
        &self,
        owners: &[SemanticId],
        candidates: &[(SemanticId, SemanticId)],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<crate::analyzer::resolution::DeferredMemberOwnerProof>>> {
        go_members::owner_proofs(self, owners, candidates, cancellation)
    }

    fn unindexed_model_callable_result(
        &self,
        frontier: &crate::analyzer::resolution::UnindexedExternalFrontier,
        cancellation: &CancellationToken,
        session: Option<
            &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
        >,
    ) -> StoreResult<Option<Option<String>>> {
        self.read_unindexed_model_callable_result(frontier, cancellation, session)
    }

    fn go_model_owner_declarations(
        &self,
        definition: SemanticId,
        owner: &crate::analyzer::resolution::ExternalOwnerIdentity,
        cancellation: &CancellationToken,
    ) -> StoreResult<
        Option<Option<crate::analyzer::resolution::fact_source::GoModelOwnerDeclarations>>,
    > {
        self.read_go_model_owner_declarations(definition, owner, cancellation)
    }

    fn go_member_declarations(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<crate::analyzer::resolution::GoMemberDeclaration>>> {
        go_members::read(self, definitions, cancellation)
    }

    fn hierarchy_terminal_nodes(
        &self,
        gaps: &[SelectedGapReasonProvenance],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(SemanticId, BindingNodeId)>>> {
        assert!(gaps.len() <= crate::analyzer::resolution::MAX_TYPED_FACT_REQUESTS_PER_BATCH);
        let lexical = super::resolution_lexical::SelectedResolutionLexicalSource::with_authority(
            self.selection,
            Rc::clone(&self.authority),
        );
        let mut rows = Vec::new();
        for gap in gaps {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            if gap.origin() != crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedHierarchyTraversal,
            ) { continue; }
            let Some(node) = lexical.node_for_identity(
                gap.fragment(),
                crate::analyzer::resolution::hierarchy_terminal_node_identity(gap.source_site()),
                cancellation,
            )?
            else {
                return Ok(None);
            };
            if let Some(node) = node {
                rows.push((gap.reason(), node));
            }
        }
        Ok((!cancellation.is_cancelled()).then_some(rows))
    }

    fn java_inheritance_declarations(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<crate::analyzer::resolution::JavaInheritanceDeclaration>>> {
        let Some(mut declarations) = java_inheritance::read(self, definitions, cancellation)?
        else {
            return Ok(None);
        };
        let Some(external) = self.external_inheritance_declarations(definitions, cancellation)?
        else {
            return Ok(None);
        };
        declarations.extend(external);
        Ok(Some(declarations))
    }

    fn rust_supertrait_owners(
        &self,
        owners: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<SemanticId>>> {
        let mut selected_owners = Vec::new();
        for &owner in owners {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let Some(ordinal) = owner.ordinal() else {
                continue;
            };
            if self
                .selection
                .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?
                .semantic_language()
                == Language::Rust
            {
                selected_owners.push(owner);
            }
        }
        Ok(Some(selected_owners))
    }

    /// Only a persisted Rust type import supplies an external type identity.
    /// Staged or non-Rust boundaries stay incomplete without an opaque value.
    fn rust_external_type_identities(
        &self,
        boundary: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<SemanticId>>> {
        let Some(ordinal) = boundary.ordinal() else {
            return Ok(Some(Vec::new()));
        };
        if self
            .selection
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?
            .semantic_language()
            != Language::Rust
        {
            return Ok(Some(Vec::new()));
        }
        let Some(provenance) = self
            .authority
            .semantic_catalog_provenance(boundary, cancellation)?
        else {
            return Ok(None);
        };
        let Some(SelectedSemanticProvenance::FragmentLocal(local)) = provenance else {
            return Ok(Some(Vec::new()));
        };
        super::resolution_operation::rust_crate_rows::external_type_identities(
            self.selection,
            (local.mount().ordinal(), local.local_key().get()),
            cancellation,
        )
    }

    fn rust_external_type_import_path(
        &self,
        boundary: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<String>>> {
        let Some(ordinal) = boundary.ordinal() else {
            return Ok(Some(Vec::new()));
        };
        if self
            .selection
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?
            .semantic_language()
            != Language::Rust
        {
            return Ok(Some(Vec::new()));
        }
        let Some(provenance) = self
            .authority
            .semantic_catalog_provenance(boundary, cancellation)?
        else {
            return Ok(None);
        };
        let Some(SelectedSemanticProvenance::FragmentLocal(local)) = provenance else {
            return Ok(Some(Vec::new()));
        };
        super::resolution_operation::rust_crate_rows::external_type_import_path(
            self.selection,
            (local.mount().ordinal(), local.local_key().get()),
            cancellation,
        )
    }

    fn namespace_definitions(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<SemanticId>> {
        // Most languages do not opt in. In particular, JVM/Rust/Go-only
        // selections must not even read a mount for namespace classification.
        if self.namespace_classifiers.is_empty() {
            return Ok(Vec::new());
        }
        let mut batches = vec![Vec::new(); self.namespace_classifiers.len()];
        for &definition in definitions {
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            let Some(ordinal) = definition.ordinal() else {
                continue;
            };
            let mount = self.selection.mount_record_by_ordinal(
                crate::analyzer::resolution::SelectedResolutionMountOrdinal::new(ordinal),
            )?;
            if let Some(index) = self
                .namespace_classifiers
                .iter()
                .position(|(language, _)| language == mount.storage_language())
            {
                batches[index].push(definition);
            }
        }
        let mut namespaces = Vec::new();
        for ((_, classifier), batch) in self.namespace_classifiers.iter().zip(batches) {
            if !batch.is_empty() {
                namespaces.extend(classifier.definitions(self.selection, &batch, cancellation)?);
            }
        }
        Ok(namespaces)
    }

    fn module_definitions(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<SemanticId>> {
        let mut modules = Vec::new();
        for provider in self.selection.module_definition_providers() {
            modules.extend(provider(self, definitions, cancellation)?);
        }
        Ok(modules)
    }

    /// One statement over the source module rows for the whole batch. A
    /// definition without a mount-local key (staged content, a shared name)
    /// has no persisted module row, and answers as not a module.
    fn rust_module_definitions(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<SemanticId>> {
        if cancellation.is_cancelled() {
            return Ok(Vec::new());
        }
        let keyed = definitions
            .iter()
            .filter_map(|&definition| {
                Some((
                    definition,
                    SelectedResolutionMountOrdinal::new(definition.ordinal()?),
                    i64::from(definition.local_key()?),
                ))
            })
            .collect::<Vec<_>>();
        super::resolution_operation::rust_crate_rows::module_definitions(self.selection, &keyed)
    }

    fn visit_selected_fragment_pages(
        &self,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, BindingFragmentId>,
    ) -> StoreResult<TypedFactReadOutcome> {
        if !self.validate_selected_interiors(cancellation)? {
            return Ok(TypedFactReadOutcome::cancelled(
                ResolutionCompletion::Complete,
            ));
        }
        let outcome = crate::analyzer::resolution::visit_mapped_typed_pages(
            self.selection.mounts()?,
            PAGE_ROWS,
            cancellation,
            |mount| mount.fragment_id(),
            visitor,
        )?;
        Ok(
            if outcome.is_exhausted() && !self.validate_selected_interiors(cancellation)? {
                TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete)
            } else {
                outcome
            },
        )
    }

    fn read_selected_reverse_inventory_completion(
        &self,
        cancellation: &CancellationToken,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.empty_outcome(cancellation)
    }

    fn visit_rust_reference_context_pages(
        &self,
        references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredRustReferenceContext>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    references.as_slice(),
                    TypedFactRelation::RustReferenceContext,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    rust_authority::REFERENCES_SQL,
                    cancellation,
                    visitor,
                    decode_rust_reference_context,
                )
            },
            |visitor| {
                super::resolution_stage::rust_context::visit_rust_reference_context_pages(
                    self.selection,
                    references,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_rust_declaration_authority_pages(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredRustDeclarationAuthority>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let Some(mounts) = self.local_keys_by_mount(
            definitions.as_slice(),
            TypedFactRelation::RustDeclarationAuthority,
            cancellation,
        )?
        else {
            return cancelled();
        };
        self.visit_typed_rows(
            &mounts,
            rust_authority::DECLARATIONS_SQL,
            cancellation,
            visitor,
            decode_rust_declaration_authority,
        )
    }

    fn visit_typed_frontier_pages(
        &self,
        slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypedFrontier>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let source = self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    slots.as_slice(),
                    TypedFactRelation::TypedFrontierSlot,
                    cancellation,
                )
            },
            typed_rows::TYPE_FRONTIERS_BY_SLOT_SQL,
            |context, row| {
                Ok(SelectedTypedRow::new(
                    context.fragment,
                    typed_rows::decode_type_frontier(
                        context,
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                    ),
                ))
            },
            |visitor| {
                super::resolution_stage::typed::visit_typed_frontier_pages(
                    self.selection,
                    slots,
                    cancellation,
                    visitor,
                )
            },
        )?;
        if !source.is_exhausted() {
            return Ok(source);
        }
        self.visit_external_type_frontiers(slots.as_slice(), cancellation, visitor)
    }

    fn visit_type_identity_observation_pages_for_references(
        &self,
        references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypedFrontier>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.visit_local_and_staged_typed_rows(
            cancellation, visitor, |source, cancellation| source.local_keys_by_mount(
                references.as_slice(), TypedFactRelation::TypeIdentityObservationReference, cancellation,
            ), typed_rows::TYPE_FRONTIERS_BY_REFERENCE_SQL, |context, row| {
                Ok(SelectedTypedRow::new(context.fragment, typed_rows::decode_type_frontier(context, row.get(0)?, row.get(1)?, row.get(2)?)))
            }, |visitor| super::resolution_stage::typed::visit_type_identity_observation_pages_for_references(
                self.selection, references, cancellation, visitor,
            ),
        )
    }

    fn visit_type_frontier_completion_pages(
        &self,
        frontiers: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypeFrontierCompletion>,
    ) -> StoreResult<TypedFactReadOutcome> {
        // Ordinary frontier slots are local catalog coordinates. Shared keys
        // belong to the stage arm and must not expand discarded memberships.
        let ordinary = frontiers
            .as_slice()
            .iter()
            .copied()
            .filter(|semantic| semantic.shared_name_id().is_none())
            .collect::<Vec<_>>();
        let Some(mounts) = self.local_keys_by_mount(
            &ordinary,
            TypedFactRelation::TypeFrontierCompletionFrontier,
            cancellation,
        )?
        else {
            return cancelled();
        };
        // Catalog provenance checks the exact publication before looking up a
        // local key, so a lost requested publication cannot disappear as an
        // absent coordinate. Check each resulting host's source visibility too.
        for (host, _) in &mounts {
            let mount = self.mount(*host)?;
            if self
                .authority
                .ensure_authority(&mount, cancellation)?
                .is_none()
            {
                return cancelled();
            }
            let Some(ready) = self.read_statement(cancellation, |connection| {
                Ok(Some(
                    connection
                        .prepare_cached(FRONTIER_SOURCE_READY_SQL)?
                        .exists([mount.blob_id()])?,
                ))
            })?
            else {
                return cancelled();
            };
            if !ready {
                return Err(StoreError::stale_resolution(
                    "requested frontier source facts are unavailable",
                ));
            }
        }
        let mut main_requests = Vec::new();
        let mut hosts = Vec::new();
        for (host, keys) in mounts {
            let base =
                super::resolution_stage::codec::encode_semantic(SemanticId::local(host.get(), 0));
            hosts.push(host.get());
            for key in keys {
                main_requests.push(serde_json::json!([host.get(), key, base]));
            }
        }
        // The frontier read drops the reasons the stage closed, and a
        // derive-helper gap closes only once its declaration is decided.
        if !self
            .selection
            .decide_derive_helpers_of_mounts(hosts, cancellation)?
        {
            return cancelled();
        }
        let main_requests =
            serde_json::to_string(&main_requests).expect("frontier main request JSON");
        super::resolution_stage::frontier_completion::visit_frontier_completion(
            self.selection,
            &main_requests,
            frontiers,
            cancellation,
            visitor,
        )
    }

    fn visit_type_transfer_pages_from_sources(
        &self,
        source_slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeTransfer>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    source_slots.as_slice(),
                    TypedFactRelation::TypeTransferSourceSlot,
                    cancellation,
                )
            },
            typed_rows::TYPE_TRANSFERS_BY_SOURCE_SQL,
            decode_transfer,
            |visitor| {
                super::resolution_stage::typed::visit_type_transfer_pages_from_sources(
                    self.selection,
                    source_slots,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_type_transfer_pages_to_targets(
        &self,
        target_slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeTransfer>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    target_slots.as_slice(),
                    TypedFactRelation::TypeTransferTargetSlot,
                    cancellation,
                )
            },
            typed_rows::TYPE_TRANSFERS_BY_TARGET_SQL,
            decode_transfer,
            |visitor| {
                super::resolution_stage::typed::visit_type_transfer_pages_to_targets(
                    self.selection,
                    target_slots,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_type_production_pages_for_outputs(
        &self,
        outputs: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeProduction>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let Some(mounts) = self.local_keys_by_mount(
            outputs.as_slice(),
            TypedFactRelation::TypeProductionOutput,
            cancellation,
        )?
        else {
            return cancelled();
        };
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                self.visit_typed_rows(&mounts, typed_rows::TYPE_PRODUCTIONS_BY_OUTPUT_SQL, cancellation, visitor, |context, row| {
                Ok(SelectedTypedRow::new(context.fragment, LoweredTypeProduction {
                    output: context.semantic(row.get(0)?),
                    element: context.semantic(row.get(3)?),
                    constructor: super::resolution_prepare::resolution_rows::from_code(brokk_bifrost_core::analyzer::resolution_facts::ALL_RESOLUTION_TYPE_CONSTRUCTOR_KINDS, row.get(1)?, "type production constructor"),
                    length: row.get(2)?,
                }))
            })
            },
            |visitor| {
                super::resolution_stage::typed::visit_type_production_pages_for_outputs(
                    self.selection,
                    outputs,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_type_component_pages_for_containers(
        &self,
        containers: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeComponent>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let Some(mounts) = self.local_keys_by_mount(
            containers.as_slice(),
            TypedFactRelation::TypeComponentContainer,
            cancellation,
        )?
        else {
            return cancelled();
        };
        let source = visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::TYPE_COMPONENTS_BY_CONTAINER_SQL,
                    cancellation,
                    visitor,
                    |context, row| {
                        Ok(SelectedTypedRow::new(
                            context.fragment,
                            typed_rows::decode_type_component(
                                context,
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3)?,
                            ),
                        ))
                    },
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_type_component_pages_for_containers(
                    self.selection,
                    containers,
                    cancellation,
                    visitor,
                )
            },
        )?;
        if !source.is_exhausted() {
            return Ok(source);
        }
        self.visit_external_type_components(containers.as_slice(), cancellation, visitor)
    }

    fn visit_declared_type_argument_pages_for_owners(
        &self,
        owners: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeclaredTypeArgument>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let Some(mounts) = self.local_keys_by_mount(
            owners.as_slice(),
            TypedFactRelation::DeclaredTypeArgumentOwner,
            cancellation,
        )?
        else {
            return cancelled();
        };
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::DECLARED_TYPE_ARGUMENTS_BY_OWNER_SQL,
                    cancellation,
                    visitor,
                    |context, row| {
                        Ok(SelectedTypedRow::new(
                            context.fragment,
                            LoweredDeclaredTypeArgument::new(
                                context.semantic(row.get(0)?),
                                u32::try_from(row.get::<_, i64>(1)?)
                                    .expect("declared type argument ordinal fits u32"),
                                context.semantic(row.get(2)?),
                            ),
                        ))
                    },
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_declared_type_argument_pages_for_owners(
                    self.selection,
                    owners,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_type_argument_pages_for_applications(
        &self,
        applications: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeArgument>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let Some(mounts) = self.local_keys_by_mount(
            applications.as_slice(),
            TypedFactRelation::TypeArgumentApplication,
            cancellation,
        )?
        else {
            return cancelled();
        };
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::TYPE_ARGUMENTS_BY_APPLICATION_SQL,
                    cancellation,
                    visitor,
                    |context, row| {
                        Ok(SelectedTypedRow::new(
                            context.fragment,
                            typed_rows::decode_type_argument(
                                context,
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3)?,
                                row.get(4)?,
                            ),
                        ))
                    },
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_type_argument_pages_for_applications(
                    self.selection,
                    applications,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_generic_type_alias_parameter_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredGenericTypeAliasParameter>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let Some(mounts) = self.local_keys_by_mount(
            definitions.as_slice(),
            TypedFactRelation::GenericTypeAliasDefinition,
            cancellation,
        )?
        else {
            return cancelled();
        };
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::GENERIC_TYPE_ALIAS_PARAMETERS_BY_ALIAS_SQL,
                    cancellation,
                    visitor,
                    |context, row| {
                        Ok(SelectedTypedRow::new(
                            context.fragment,
                            typed_rows::decode_generic_type_alias_parameter(
                                context,
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3)?,
                                row.get(4)?,
                                row.get(5)?,
                            ),
                        ))
                    },
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_generic_type_alias_parameter_pages_for_definitions(
                    self.selection,
                    definitions,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_generic_formal_pages_for_owners(
        &self,
        owners: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredGenericFormal>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let Some(mounts) = self.local_keys_by_mount(
            owners.as_slice(),
            TypedFactRelation::GenericFormalOwner,
            cancellation,
        )?
        else {
            return cancelled();
        };
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::GENERIC_FORMALS_BY_OWNER_SQL,
                    cancellation,
                    visitor,
                    |context, row| {
                        Ok(SelectedTypedRow::new(
                            context.fragment,
                            LoweredGenericFormal::new(
                                context.semantic(row.get(0)?),
                                u32::try_from(row.get::<_, i64>(1)?)
                                    .expect("stored generic formal ordinal fits u32"),
                                context.semantic(row.get(2)?),
                            ),
                        ))
                    },
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_generic_formal_pages_for_owners(
                    self.selection,
                    owners,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_generic_formal_default_pages_for_owners(
        &self,
        owners: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredGenericFormalDefault>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let Some(mounts) = self.local_keys_by_mount(
            owners.as_slice(),
            TypedFactRelation::GenericFormalDefaultOwner,
            cancellation,
        )?
        else {
            return cancelled();
        };
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::GENERIC_FORMAL_DEFAULTS_BY_OWNER_SQL,
                    cancellation,
                    visitor,
                    |context, row| {
                        Ok(SelectedTypedRow::new(
                            context.fragment,
                            LoweredGenericFormalDefault::new(
                                context.semantic(row.get(0)?),
                                u32::try_from(row.get::<_, i64>(1)?)
                                    .expect("stored generic formal ordinal fits u32"),
                                context.semantic(row.get(2)?),
                            ),
                        ))
                    },
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_generic_formal_default_pages_for_owners(
                    self.selection,
                    owners,
                    cancellation,
                    visitor,
                )
            },
        )
    }
    fn visit_underlying_type_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredUnderlyingType>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let Some(mounts) = self.local_keys_by_mount(
            definitions.as_slice(),
            TypedFactRelation::UnderlyingTypeDefinition,
            cancellation,
        )?
        else {
            return cancelled();
        };
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::UNDERLYING_TYPES_BY_DEFINITION_SQL,
                    cancellation,
                    visitor,
                    |context, row| {
                        Ok(SelectedTypedRow::new(
                            context.fragment,
                            typed_rows::decode_underlying_type(context, row.get(0)?, row.get(1)?),
                        ))
                    },
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_underlying_type_pages_for_definitions(
                    self.selection,
                    definitions,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_intrinsic_seed_pages_for_slots(
        &self,
        slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredIntrinsicSeed>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let source = self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    slots.as_slice(),
                    TypedFactRelation::IntrinsicSeedSlot,
                    cancellation,
                )
            },
            typed_rows::INTRINSIC_SEEDS_BY_SLOT_SQL,
            decode_intrinsic_seed,
            |visitor| {
                super::resolution_stage::typed::visit_intrinsic_seed_pages_for_slots(
                    self.selection,
                    slots,
                    cancellation,
                    visitor,
                )
            },
        )?;
        if !source.is_exhausted() {
            return Ok(source);
        }
        self.visit_external_type_seeds(slots.as_slice(), cancellation, visitor)
    }

    fn visit_intrinsic_seed_pages_for_type_identities(
        &self,
        type_identities: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredIntrinsicSeed>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                // Membership is the discriminating relation here, not an overshoot.
                // An intrinsic type identity enters a blob's identity catalog only
                // where lowering builds an intrinsic seed for it
                // (`typed_fact_lowering.rs`, the one construction site), so the blobs
                // that mention such an identity are exactly the blobs that seed it.
                let Some(mounts) = self.shared_keys_by_mount(
                    type_identities.as_slice(),
                    TypedFactRelation::IntrinsicSeedTypeIdentity,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::INTRINSIC_SEEDS_BY_IDENTITY_SQL,
                    cancellation,
                    visitor,
                    decode_intrinsic_seed,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_intrinsic_seed_pages_for_type_identities(
                    self.selection,
                    type_identities,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_intrinsic_type_descriptor_pages_for_type_identities(
        &self,
        type_identities: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredIntrinsicTypeDescriptor>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let source = self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.shared_keys_by_mount(
                    type_identities.as_slice(),
                    TypedFactRelation::IntrinsicSeedTypeIdentity,
                    cancellation,
                )
            },
            typed_rows::INTRINSIC_TYPE_DESCRIPTORS_BY_IDENTITY_SQL,
            decode_intrinsic_type_descriptor,
            |visitor| {
                super::resolution_stage::typed::visit_intrinsic_type_descriptor_pages_for_type_identities(
                    self.selection,
                    type_identities,
                    cancellation,
                    visitor,
                )
            },
        )?;
        if !source.is_exhausted() {
            return Ok(source);
        }
        self.visit_external_type_descriptors(type_identities.as_slice(), cancellation, visitor)
    }

    fn visit_binding_projection_pages_for_references(
        &self,
        references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredBindingProjection>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    references.as_slice(),
                    TypedFactRelation::BindingProjectionReference,
                    cancellation,
                )
            },
            typed_rows::BINDING_PROJECTIONS_BY_REFERENCE_SQL,
            decode_binding_projection,
            |visitor| {
                super::resolution_stage::typed::visit_binding_projection_pages_for_references(
                    self.selection,
                    references,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_binding_projection_pages_for_outputs(
        &self,
        output_slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredBindingProjection>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    output_slots.as_slice(),
                    TypedFactRelation::BindingProjectionOutputSlot,
                    cancellation,
                )
            },
            typed_rows::BINDING_PROJECTIONS_BY_OUTPUT_SQL,
            decode_binding_projection,
            |visitor| {
                super::resolution_stage::typed::visit_binding_projection_pages_for_outputs(
                    self.selection,
                    output_slots,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_qualified_route_pages_for_references(
        &self,
        references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    references.as_slice(),
                    TypedFactRelation::QualifiedRouteReference,
                    cancellation,
                )
            },
            typed_rows::QUALIFIED_ROUTES_BY_REFERENCE_SQL,
            decode_qualified_route,
            |visitor| {
                super::resolution_stage::typed::visit_qualified_route_pages_for_references(
                    self.selection,
                    references,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    /// Select exact qualifier slots paired with either the source lookup or
    /// the typed member lookup.
    ///
    /// The pair is the key, not the lookup alone: the interior indexes a route
    /// under `(qualifier_slot, lookup)` and lane CM's rule is that a rows
    /// reader reproduces the in-memory index's exact key. The mounts come from
    /// the lookup relation, because a blob answers only when it holds a route
    /// under the requested lookup and a qualifier slot cannot add a blob that
    /// relation omits; inside a blob, only a pair whose qualifier slot is that
    /// blob's own can match, which is what grouping the slot coordinates does.
    fn visit_qualified_route_pages_for_slot_lookups(
        &self,
        requests: TypedFactRequest<'_, QualifiedRouteSlotLookup>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let slots = requests
                    .as_slice()
                    .iter()
                    .map(|request| request.qualifier_slot())
                    .collect::<Vec<_>>();
                let lookups = requests
                    .as_slice()
                    .iter()
                    .map(|request| request.lookup())
                    .collect::<Vec<_>>();
                let Some(slot_coordinates) = self.semantic_coordinates(
                    &slots,
                    TypedFactRelation::QualifiedRouteQualifierSlot,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                let Some(route_mounts) = self.interior_mounts_for_semantics(
                    &lookups,
                    TypedFactRelation::QualifiedRouteLookup,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                let names = self
                    .selection
                    .shared_name_table()
                    .interner(self.selection.connection());
                let mut evidence = PolledCompletionAccumulator::new(cancellation);
                for ordinal in route_mounts {
                    let mount = &*self.mount(ordinal)?;
                    let pairs = slot_coordinates
                        .iter()
                        .filter(|coordinate| {
                            coordinate.mount == ordinal
                                && coordinate.space == RequestKeySpace::Local
                        })
                        .filter_map(|coordinate| {
                            lookups[coordinate.request_ordinal]
                                .shared_name_id()
                                .and_then(|name| names.to_persisted(name))
                                .map(|lookup| (coordinate.keys[0], i64::from(lookup.get())))
                        })
                        .collect::<Vec<_>>();
                    if pairs.is_empty() {
                        continue;
                    }
                    let pair_array = json_pair_array(pairs.into_iter());
                    let Some(rows) = self.decode_page(
                        mount,
                        typed_rows::QUALIFIED_ROUTES_BY_SLOT_LOOKUP_SQL,
                        &[&mount.blob_id() as &dyn rusqlite::ToSql, &pair_array],
                        cancellation,
                        &decode_qualified_route,
                        &mut evidence,
                    )?
                    else {
                        return Ok(TypedFactReadOutcome::cancelled(
                            evidence.finish_semantic().0,
                        ));
                    };
                    match Self::page_out(&rows, cancellation, visitor)? {
                        PageOutcome::Exhausted => {}
                        PageOutcome::Stopped => {
                            let (completion, cancelled) = evidence.finish_semantic();
                            return Ok(if cancelled {
                                TypedFactReadOutcome::cancelled(completion)
                            } else {
                                TypedFactReadOutcome::stopped(completion)
                            });
                        }
                        PageOutcome::Cancelled => {
                            return Ok(TypedFactReadOutcome::cancelled(
                                evidence.finish_semantic().0,
                            ));
                        }
                    }
                }
                Ok(if cancellation.is_cancelled() {
                    TypedFactReadOutcome::cancelled(evidence.finish_semantic().0)
                } else {
                    TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
                })
            },
            |visitor| {
                super::resolution_stage::typed::visit_qualified_route_pages_for_slot_lookups(
                    self.selection,
                    requests,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_qualified_route_pages_for_qualifier_slots(
        &self,
        qualifier_slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    qualifier_slots.as_slice(),
                    TypedFactRelation::QualifiedRouteQualifierSlot,
                    cancellation,
                )
            },
            typed_rows::QUALIFIED_ROUTES_BY_QUALIFIER_SLOT_SQL,
            decode_qualified_route,
            |visitor| {
                super::resolution_stage::typed::visit_qualified_route_pages_for_qualifier_slots(
                    self.selection,
                    qualifier_slots,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_qualified_route_pages_for_lookups(
        &self,
        lookups: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.shared_keys_by_mount(
                    lookups.as_slice(),
                    TypedFactRelation::QualifiedRouteLookup,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                // A route answers under its member lookup and, when they differ,
                // under its source lookup. The statement tests both inside the blob's
                // own route prefix rather than through two indexes: this question has
                // no measured caller, and an index exists only for a statement that is
                // reached (owner decision, 2026-09-19).
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::QUALIFIED_ROUTES_BY_LOOKUP_SQL,
                    cancellation,
                    visitor,
                    decode_qualified_route,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_qualified_route_pages_for_lookups(
                    self.selection,
                    lookups,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_qualified_route_pages_for_gap_reasons(
        &self,
        reasons: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    reasons.as_slice(),
                    TypedFactRelation::QualifiedRouteGapReason,
                    cancellation,
                )
            },
            typed_rows::QUALIFIED_ROUTES_BY_GAP_REASON_SQL,
            decode_qualified_route,
            |visitor| {
                super::resolution_stage::typed::visit_qualified_route_pages_for_gap_reasons(
                    self.selection,
                    reasons,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_qualified_route_inventory_pages(
        &self,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.interior_mounts_holding_a_qualified_route(cancellation)?
                else {
                    return cancelled();
                };
                self.visit_typed_rows_in_mounts(
                    &mounts,
                    typed_rows::QUALIFIED_ROUTES_INVENTORY_SQL,
                    cancellation,
                    visitor,
                    decode_qualified_route,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_qualified_route_inventory_pages(
                    self.selection,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_declaration_type_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeclarationTypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let source = self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    definitions.as_slice(),
                    TypedFactRelation::DeclarationTypeDefinition,
                    cancellation,
                )
            },
            typed_rows::DECLARATION_TYPES_BY_DEFINITION_SQL,
            decode_declaration_type,
            |visitor| {
                super::resolution_stage::typed::visit_declaration_type_pages_for_definitions(
                    self.selection,
                    definitions,
                    cancellation,
                    visitor,
                )
            },
        )?;
        if !source.is_exhausted() {
            return Ok(source);
        }
        self.visit_external_declaration_types(definitions.as_slice(), cancellation, visitor)
    }

    fn visit_declaration_type_pages_for_slots(
        &self,
        slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeclarationTypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let source = self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    slots.as_slice(),
                    TypedFactRelation::DeclarationTypeSlot,
                    cancellation,
                )
            },
            typed_rows::DECLARATION_TYPES_BY_SLOT_SQL,
            decode_declaration_type,
            |visitor| {
                super::resolution_stage::typed::visit_declaration_type_pages_for_slots(
                    self.selection,
                    slots,
                    cancellation,
                    visitor,
                )
            },
        )?;
        if !source.is_exhausted() {
            return Ok(source);
        }
        self.visit_external_declaration_types_for_slots(slots.as_slice(), cancellation, visitor)
    }

    /// Question 45 keeps the view it already has over the source declaration
    /// properties (draft section 6), so this reader adds no table.
    fn visit_declaration_visibility_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<
            '_,
            SelectedTypedRow<LoweredDeclarationVisibilityProperty>,
        >,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    definitions.as_slice(),
                    TypedFactRelation::DeclarationVisibilityDefinition,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                &mounts,
                typed_rows::DECLARATION_VISIBILITIES_BY_DEFINITION_SQL,
                cancellation,
                visitor,
                |context, row| {
                    let label: String = row.get(1)?;
                    use brokk_bifrost_core::analyzer::source_facts::DeclarationAccessBoundary;
                    let boundary = match row.get::<_, Option<i64>>(2)? {
                        None => None,
                        Some(0) => Some(DeclarationAccessBoundary::Package(row.get(3)?)),
                        Some(1) => Some(DeclarationAccessBoundary::Template(context.semantic(row.get(4)?))),
                        kind => return Err(invalid_fact(format!("stored access boundary kind {kind:?} is outside its vocabulary"))),
                    };
                    Ok(SelectedTypedRow::new(
                        context.fragment,
                        LoweredDeclarationVisibilityProperty::new(
                            context.semantic(row.get(0)?),
                            DeclaredVisibility::from_label(&label).ok_or_else(|| {
                                invalid_fact(format!(
                                    "stored declaration visibility {label:?} is outside its vocabulary"
                                ))
                            })?,
                        ).with_boundary(boundary),
                    ))
                },
            )
            },
            |visitor| {
                super::resolution_stage::typed::visit_declaration_visibility_pages_for_definitions(
                    self.selection,
                    definitions,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_member_scope_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberScopeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let source = self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    definitions.as_slice(),
                    TypedFactRelation::MemberScopeDefinition,
                    cancellation,
                )
            },
            typed_rows::MEMBER_SCOPES_BY_DEFINITION_SQL,
            decode_member_scope,
            |visitor| {
                super::resolution_stage::typed::visit_member_scope_pages_for_definitions(
                    self.selection,
                    definitions,
                    cancellation,
                    visitor,
                )
            },
        )?;
        if !source.is_exhausted() {
            return Ok(source);
        }
        let external =
            self.visit_external_member_scopes(definitions.as_slice(), cancellation, visitor)?;
        let completion = source.evidence().combine(external.evidence());
        Ok(match external.terminal() {
            crate::analyzer::resolution::TypedFactReadTerminal::Exhausted => {
                TypedFactReadOutcome::exhausted(completion)
            }
            crate::analyzer::resolution::TypedFactReadTerminal::Stopped => {
                TypedFactReadOutcome::stopped(completion)
            }
            crate::analyzer::resolution::TypedFactReadTerminal::Cancelled => {
                TypedFactReadOutcome::cancelled(completion)
            }
        })
    }

    fn visit_jvm_alias_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<JvmAliasProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let Some(mounts) = self.local_keys_by_mount(
            definitions.as_slice(),
            TypedFactRelation::DeclarationVisibilityDefinition,
            cancellation,
        )?
        else {
            return cancelled();
        };
        // These are existing blob-local alias rows. No staged or external
        // alias definitions are manufactured for an authored source request.
        self.visit_typed_rows(
            &mounts,
            typed_rows::JVM_ALIASES_BY_DEFINITION_SQL,
            cancellation,
            visitor,
            |context, row| {
                use brokk_bifrost_core::analyzer::resolution_facts::{
                    ResolutionJvmAliasKind, ResolutionJvmAliasStatus,
                };
                let kind: String = row.get(3)?;
                let status: String = row.get(4)?;
                let owners: String = row.get(5)?;
                Ok(SelectedTypedRow::new(
                    context.fragment,
                    JvmAliasProperty {
                        definition: context.semantic(row.get(0)?),
                        alias: row.get(1)?,
                        member_name: row.get(2)?,
                        kind: ResolutionJvmAliasKind::from_label(&kind).ok_or_else(|| {
                            invalid_fact(format!("invalid JVM alias kind {kind:?}"))
                        })?,
                        status: ResolutionJvmAliasStatus::from_label(&status).ok_or_else(|| {
                            invalid_fact(format!("invalid JVM alias status {status:?}"))
                        })?,
                        owner_segments: serde_json::from_str(&owners).map_err(|error| {
                            invalid_fact(format!("invalid JVM alias owner segments: {error}"))
                        })?,
                    },
                ))
            },
        )
    }

    fn visit_companion_relation_pages_for_enclosing_types(
        &self,
        enclosing_types: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<CompanionTypeRelation>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    enclosing_types.as_slice(),
                    TypedFactRelation::MemberScopeDefinition,
                    cancellation,
                )
            },
            typed_rows::COMPANION_RELATIONS_BY_ENCLOSING_TYPE_SQL,
            decode_companion_relation,
            |visitor| {
                let _ = visitor;
                Ok(if cancellation.is_cancelled() {
                    TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete)
                } else {
                    TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
                })
            },
        )
    }

    fn visit_member_scope_pages_for_heads(
        &self,
        heads: TypedFactRequest<'_, BindingNodeId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberScopeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| source.node_keys_by_mount(heads.as_slice(), cancellation),
            typed_rows::MEMBER_SCOPES_BY_HEAD_SQL,
            decode_member_scope,
            |visitor| {
                super::resolution_stage::typed::visit_member_scope_pages_for_heads(
                    self.selection,
                    heads,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_member_owner_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberOwnerProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let source = self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    definitions.as_slice(),
                    TypedFactRelation::MemberOwnerDefinition,
                    cancellation,
                )
            },
            typed_rows::MEMBER_OWNERS_BY_DEFINITION_SQL,
            decode_member_owner,
            |visitor| {
                super::resolution_stage::typed::visit_member_owner_pages_for_definitions(
                    self.selection,
                    definitions,
                    cancellation,
                    visitor,
                )
            },
        )?;
        if !source.is_exhausted() {
            return Ok(source);
        }
        let external = self.visit_external_member_owners_for_definitions(
            definitions.as_slice(),
            cancellation,
            visitor,
        )?;
        let completion = source.evidence().combine(external.evidence());
        Ok(match external.terminal() {
            crate::analyzer::resolution::TypedFactReadTerminal::Exhausted => {
                TypedFactReadOutcome::exhausted(completion)
            }
            crate::analyzer::resolution::TypedFactReadTerminal::Stopped => {
                TypedFactReadOutcome::stopped(completion)
            }
            crate::analyzer::resolution::TypedFactReadTerminal::Cancelled => {
                TypedFactReadOutcome::cancelled(completion)
            }
        })
    }

    fn visit_member_owner_pages_for_owners(
        &self,
        owner_definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberOwnerProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let source = self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    owner_definitions.as_slice(),
                    TypedFactRelation::MemberOwnerOwnerDefinition,
                    cancellation,
                )
            },
            typed_rows::MEMBER_OWNERS_BY_OWNER_SQL,
            decode_member_owner,
            |visitor| {
                super::resolution_stage::typed::visit_member_owner_pages_for_owners(
                    self.selection,
                    owner_definitions,
                    cancellation,
                    visitor,
                )
            },
        )?;
        if !source.is_exhausted() {
            return Ok(source);
        }
        let external =
            self.visit_external_member_owners(owner_definitions.as_slice(), cancellation, visitor)?;
        let completion = source.evidence().combine(external.evidence());
        Ok(match external.terminal() {
            crate::analyzer::resolution::TypedFactReadTerminal::Exhausted => {
                TypedFactReadOutcome::exhausted(completion)
            }
            crate::analyzer::resolution::TypedFactReadTerminal::Stopped => {
                TypedFactReadOutcome::stopped(completion)
            }
            crate::analyzer::resolution::TypedFactReadTerminal::Cancelled => {
                TypedFactReadOutcome::cancelled(completion)
            }
        })
    }

    fn visit_deferred_member_owner_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeferredMemberOwner>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    definitions.as_slice(),
                    TypedFactRelation::DeferredMemberOwnerDefinition,
                    cancellation,
                )
            },
            typed_rows::DEFERRED_MEMBER_OWNERS_BY_DEFINITION_SQL,
            decode_deferred_member_owner,
            |visitor| {
                super::resolution_stage::typed::visit_deferred_member_owner_pages_for_definitions(
                    self.selection,
                    definitions,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_deferred_member_owner_pages_for_lookup_names(
        &self,
        lookups: TypedFactRequest<'_, DeferredMemberOwnerLookupName>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeferredMemberOwner>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                let semantics = lookups
                    .as_slice()
                    .iter()
                    .map(|lookup| lookup.lookup())
                    .collect::<Vec<_>>();
                source.shared_keys_by_mount(
                    &semantics,
                    TypedFactRelation::DeferredMemberOwnerLookup,
                    cancellation,
                )
            },
            typed_rows::DEFERRED_MEMBER_OWNERS_BY_LOOKUP_SQL,
            decode_deferred_member_owner,
            |visitor| {
                super::resolution_stage::typed::visit_deferred_member_owner_pages_for_lookup_names(
                    self.selection,
                    lookups,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_construction_requirement_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<
            '_,
            SelectedTypedRow<LoweredConstructionRequirementProperty>,
        >,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.visit_local_and_staged_typed_rows(
            cancellation, visitor, |source, cancellation| source.local_keys_by_mount(
                definitions.as_slice(), TypedFactRelation::ConstructionRequirementDefinition, cancellation,
            ), typed_rows::CONSTRUCTION_REQUIREMENTS_BY_DEFINITION_SQL, |context, row| {
                Ok(SelectedTypedRow::new(context.fragment, typed_rows::decode_construction_requirement(context, row.get(0)?, row.get(1)?, row.get(2)?)))
            }, |visitor| super::resolution_stage::typed::visit_construction_requirement_pages_for_definitions(
                self.selection, definitions, cancellation, visitor,
            ),
        )
    }

    fn visit_supertype_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredSupertypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let source = self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    definitions.as_slice(),
                    TypedFactRelation::SupertypeDefinition,
                    cancellation,
                )
            },
            typed_rows::SUPERTYPES_BY_DEFINITION_SQL,
            decode_supertype,
            |visitor| {
                super::resolution_stage::typed::visit_supertype_pages_for_definitions(
                    self.selection,
                    definitions,
                    cancellation,
                    visitor,
                )
            },
        )?;
        if !source.is_exhausted() {
            return Ok(source);
        }
        let external =
            self.visit_external_supertypes(definitions.as_slice(), cancellation, visitor)?;
        let completion = source.evidence().combine(external.evidence());
        Ok(match external.terminal() {
            crate::analyzer::resolution::TypedFactReadTerminal::Exhausted => {
                TypedFactReadOutcome::exhausted(completion)
            }
            crate::analyzer::resolution::TypedFactReadTerminal::Stopped => {
                TypedFactReadOutcome::stopped(completion)
            }
            crate::analyzer::resolution::TypedFactReadTerminal::Cancelled => {
                TypedFactReadOutcome::cancelled(completion)
            }
        })
    }

    fn visit_supertype_pages_for_references(
        &self,
        references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredSupertypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    references.as_slice(),
                    TypedFactRelation::SupertypeReference,
                    cancellation,
                )
            },
            typed_rows::SUPERTYPES_BY_REFERENCE_SQL,
            decode_supertype,
            |visitor| {
                super::resolution_stage::typed::visit_supertype_pages_for_references(
                    self.selection,
                    references,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_supertype_pages_for_frontiers(
        &self,
        frontiers: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredSupertypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    frontiers.as_slice(),
                    TypedFactRelation::SupertypeFrontier,
                    cancellation,
                )
            },
            typed_rows::SUPERTYPES_BY_FRONTIER_SQL,
            decode_supertype,
            |visitor| {
                super::resolution_stage::typed::visit_supertype_pages_for_frontiers(
                    self.selection,
                    frontiers,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_definition_property_gap_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDefinitionPropertyGap>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.visit_open_property_gaps(cancellation, visitor, |visitor| {
            self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    definitions.as_slice(),
                    TypedFactRelation::DefinitionPropertyGapDefinition,
                    cancellation,
                )
            },
            typed_rows::DEFINITION_PROPERTY_GAPS_BY_DEFINITION_SQL,
            |context, row| {
                Ok(SelectedTypedRow::new(
                    context.fragment,
                    typed_rows::decode_definition_property_gap(
                        context,
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ),
                ))
            },
            |visitor| {
                super::resolution_stage::typed::visit_definition_property_gap_pages_for_definitions(
                    self.selection,
                    definitions,
                    cancellation,
                    visitor,
                )
            },
        )
        })
    }

    fn visit_definition_property_gap_pages_for_reasons(
        &self,
        reasons: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDefinitionPropertyGap>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.visit_open_property_gaps(cancellation, visitor, |visitor| {
            visit_combined_typed_rows(
                cancellation,
                visitor,
                |visitor| {
                    let Some(mounts) = self.local_keys_by_mount(
                        reasons.as_slice(),
                        TypedFactRelation::DefinitionPropertyGapReason,
                        cancellation,
                    )?
                    else {
                        return cancelled();
                    };
                    self.visit_typed_rows(
                        &mounts,
                        typed_rows::DEFINITION_PROPERTY_GAPS_BY_REASON_SQL,
                        cancellation,
                        visitor,
                        |context, row| {
                            Ok(SelectedTypedRow::new(
                                context.fragment,
                                typed_rows::decode_definition_property_gap(
                                    context,
                                    row.get(0)?,
                                    row.get(1)?,
                                    row.get(2)?,
                                    row.get(3)?,
                                    row.get(4)?,
                                ),
                            ))
                        },
                    )
                },
                |visitor| {
                    super::resolution_stage::typed::visit_definition_property_gap_pages_for_reasons(
                        self.selection,
                        reasons,
                        cancellation,
                        visitor,
                    )
                },
            )
        })
    }

    fn visit_call_applicability_pages_for_callee_references(
        &self,
        callee_references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<
            '_,
            SelectedTypedRow<LoweredCallApplicabilityObligation>,
        >,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.visit_local_and_staged_typed_rows(
            cancellation, visitor, |source, cancellation| source.local_keys_by_mount(
                callee_references.as_slice(), TypedFactRelation::CallApplicabilityCalleeReference, cancellation,
            ), typed_rows::CALL_OBLIGATIONS_BY_CALLEE_SQL, decode_call_obligation, |visitor| super::resolution_stage::typed::visit_call_applicability_pages_for_callee_references(
                self.selection, callee_references, cancellation, visitor,
            ),
        )
    }

    fn visit_call_applicability_pages_for_gap_reasons(
        &self,
        reasons: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<
            '_,
            SelectedTypedRow<LoweredCallApplicabilityObligation>,
        >,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    reasons.as_slice(),
                    TypedFactRelation::CallApplicabilityGapReason,
                    cancellation,
                )
            },
            typed_rows::CALL_OBLIGATIONS_BY_REASON_SQL,
            decode_call_obligation,
            |visitor| {
                super::resolution_stage::typed::visit_call_applicability_pages_for_gap_reasons(
                    self.selection,
                    reasons,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_callable_signature_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredCallableSignatureProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let source = self.visit_local_and_staged_typed_rows(
            cancellation,
            visitor,
            |source, cancellation| {
                source.local_keys_by_mount(
                    definitions.as_slice(),
                    TypedFactRelation::CallableSignatureDefinition,
                    cancellation,
                )
            },
            typed_rows::CALLABLE_SIGNATURES_BY_DEFINITION_SQL,
            |context, row| {
                let body: String = row.get(1)?;
                Ok(SelectedTypedRow::new(
                    context.fragment,
                    typed_rows::decode_callable_signature(context, row.get(0)?, &body),
                ))
            },
            |visitor| {
                super::resolution_stage::typed::visit_callable_signature_pages_for_definitions(
                    self.selection,
                    definitions,
                    cancellation,
                    visitor,
                )
            },
        )?;
        if !source.is_exhausted() {
            return Ok(source);
        }
        self.visit_external_callable_signatures(definitions.as_slice(), cancellation, visitor)
    }

    fn visit_gap_reason_provenance_pages_for_reasons(
        &self,
        reasons: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedGapReasonProvenance>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    reasons.as_slice(),
                    TypedFactRelation::GapReasonProvenanceReason,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::GAP_REASON_PROVENANCE_SQL,
                    cancellation,
                    visitor,
                    |context, row| {
                        Ok(SelectedGapReasonProvenance::new(
                            context.fragment,
                            context.semantic(row.get(0)?),
                            brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId::new(
                                row.get(1)?,
                            ),
                            super::resolution_prepare::resolution_rows::gap_origin_from_code(
                                row.get(2)?,
                            ),
                        ))
                    },
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_gap_reason_provenance_pages_for_reasons(
                    self.selection,
                    reasons,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_rust_reason_owners(
        &self,
        reasons: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, (SemanticId, SemanticId)>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let Some(mounts) = self.local_keys_by_mount(
            reasons.as_slice(),
            TypedFactRelation::GapReasonProvenanceReason,
            cancellation,
        )?
        else {
            return cancelled();
        };
        let sql = super::resolution_operation::rust_crate_access::REASON_OWNERS_SQL;
        for (ordinal, keys) in mounts {
            let mount = &*self.mount(ordinal)?;
            let blob_id = mount.blob_id();
            let misses = {
                let memo = self.selection.authority_request_memo().borrow();
                keys.iter()
                    .copied()
                    .filter(|key| !memo.rust_reason_owners.contains_key(&(blob_id, *key)))
                    .collect::<Vec<_>>()
            };
            #[cfg(all(any(test, feature = "test-support"), debug_assertions))]
            let had_hits = misses.len() < keys.len();
            if !misses.is_empty() {
                let missing_mounts = [(ordinal, misses)];
                let mut rows = Vec::<(i64, i64)>::new();
                let outcome = self.visit_typed_rows(
                    &missing_mounts,
                    sql,
                    cancellation,
                    &mut TypedFactPageVisitor::new(&mut |page| {
                        rows.extend_from_slice(page);
                        Ok(true)
                    }),
                    |_, row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                if outcome.is_cancelled() || cancellation.is_cancelled() {
                    return cancelled();
                }
                assert!(outcome.is_exhausted(), "the collecting visitor never stops");
                let mut memo = self.selection.authority_request_memo().borrow_mut();
                for key in &missing_mounts[0].1 {
                    memo.rust_reason_owners.insert((blob_id, *key), None);
                }
                for (reason, owner) in rows {
                    let previous = memo
                        .rust_reason_owners
                        .insert((blob_id, reason), Some(owner));
                    assert_eq!(previous, Some(None), "a reason has one declaration owner");
                }
            }
            let mut raw_rows = {
                let memo = self.selection.authority_request_memo().borrow();
                keys.iter()
                    .filter_map(|key| {
                        memo.rust_reason_owners[&(blob_id, *key)].map(|owner| (*key, owner))
                    })
                    .collect::<Vec<_>>()
            };
            raw_rows.sort_unstable();
            // Test builds verify reuse against the publication, including negative
            // hits. Production never issues this extra read.
            #[cfg(all(any(test, feature = "test-support"), debug_assertions))]
            if had_hits {
                let mut fresh_rows = Vec::<(i64, i64)>::new();
                let outcome = self.visit_typed_rows(
                    &[(ordinal, keys)],
                    sql,
                    cancellation,
                    &mut TypedFactPageVisitor::new(&mut |page| {
                        fresh_rows.extend_from_slice(page);
                        Ok(true)
                    }),
                    |_, row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                if outcome.is_cancelled() || cancellation.is_cancelled() {
                    return cancelled();
                }
                debug_assert_eq!(raw_rows, fresh_rows);
            }
            let names = self
                .selection
                .shared_name_table()
                .interner(self.selection.connection());
            let context = TypedRowContext {
                fragment: mount.fragment_id(),
                ordinal: ordinal.get(),
                language: mount.semantic_language(),
                names: &names,
            };
            let rows = raw_rows
                .into_iter()
                .map(|(reason, owner)| (context.semantic(reason), context.semantic(owner)))
                .collect::<Vec<_>>();
            match Self::page_out(&rows, cancellation, visitor)? {
                PageOutcome::Exhausted => {}
                PageOutcome::Stopped => {
                    return Ok(TypedFactReadOutcome::stopped(
                        ResolutionCompletion::Complete,
                    ));
                }
                PageOutcome::Cancelled => return cancelled(),
            }
        }
        Ok(if cancellation.is_cancelled() {
            TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete)
        } else {
            TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
        })
    }
}

fn decode_rust_reference_context(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredRustReferenceContext>> {
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;
    use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceOccurrenceId};
    Ok(SelectedTypedRow::new(
        context.fragment,
        LoweredRustReferenceContext::new(
            context.semantic(row.get(0)?),
            ResolutionSiteId::new(row.get(1)?),
            SourceOccurrenceId::new(row.get(2)?),
            SourceOccurrenceId::new(row.get(3)?),
            row.get::<_, Option<u32>>(4)?.map(SourceDeclarationId::new),
        )
        .with_cfg_condition(rust_authority::decode_cfg(&row.get::<_, String>(5)?)),
    ))
}

fn decode_rust_declaration_authority(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredRustDeclarationAuthority>> {
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;
    use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceOccurrenceId};
    Ok(SelectedTypedRow::new(
        context.fragment,
        LoweredRustDeclarationAuthority::new(
            context.semantic(row.get(0)?),
            ResolutionSiteId::new(row.get(1)?),
            SourceDeclarationId::new(row.get(2)?),
            row.get::<_, Option<String>>(3)?
                .map(|body| rust_authority::decode_visibility(&body)),
            SourceOccurrenceId::new(row.get(4)?),
            row.get::<_, Option<u32>>(5)?.map(SourceDeclarationId::new),
        )
        .with_cfg_condition(rust_authority::decode_cfg(&row.get::<_, String>(6)?))
        .with_activation_reason(
            row.get::<_, Option<i64>>(7)?
                .map(|key| context.semantic(key)),
        ),
    ))
}

#[doc(hidden)]
pub fn cancelled() -> StoreResult<TypedFactReadOutcome> {
    Ok(TypedFactReadOutcome::cancelled(
        ResolutionCompletion::Complete,
    ))
}

fn decode_transfer(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredTypeTransfer>> {
    let completion: Option<String> = row.get(7)?;
    Ok(SelectedTypedRow::new(
        context.fragment,
        typed_rows::decode_type_transfer(
            context,
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            completion.as_deref(),
        ),
    ))
}

fn decode_intrinsic_seed(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredIntrinsicSeed>> {
    let spelling: String = row.get(2)?;
    let possible_values: String = row.get(3)?;
    let completion: Option<String> = row.get(4)?;
    Ok(SelectedTypedRow::new(
        context.fragment,
        typed_rows::decode_intrinsic_seed(
            context,
            row.get(0)?,
            row.get(1)?,
            &spelling,
            &possible_values,
            completion.as_deref(),
        ),
    ))
}

fn decode_intrinsic_type_descriptor(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredIntrinsicTypeDescriptor>> {
    let spelling: String = row.get(2)?;
    Ok(SelectedTypedRow::new(
        context.fragment,
        typed_rows::decode_intrinsic_type_descriptor(context, row.get(0)?, row.get(1)?, &spelling),
    ))
}

fn decode_binding_projection(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredBindingProjection>> {
    Ok(SelectedTypedRow::new(
        context.fragment,
        typed_rows::decode_binding_projection(context, row.get(0)?, row.get(1)?, row.get(2)?),
    ))
}

/// A qualified route carries its reference's lexical node.
///
/// The row does not store it: a site, its semantic and its node carry one
/// number (`local_identity.rs`, `finish`), and a route's reference is a
/// reference site, so the node is the reference key at the same mount. The
/// writer asserts the same equality where it encodes an observation.
fn decode_qualified_route(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedQualifiedRoute> {
    let reference: i64 = row.get(0)?;
    Ok(SelectedQualifiedRoute::new(
        context.fragment,
        context.node(reference),
        typed_rows::decode_qualified_route(
            context,
            reference,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            row.get(7)?,
            row.get(8)?,
            row.get(9)?,
        ),
    )
    .with_language(context.language))
}

fn decode_declaration_type(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredDeclarationTypeProperty>> {
    Ok(SelectedTypedRow::new(
        context.fragment,
        typed_rows::decode_declaration_type(context, row.get(0)?, row.get(1)?, row.get(2)?),
    ))
}

fn decode_member_scope(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredMemberScopeProperty>> {
    Ok(SelectedTypedRow::new(
        context.fragment,
        LoweredMemberScopeProperty::new(context.semantic(row.get(0)?), context.node(row.get(1)?)),
    ))
}

fn decode_companion_relation(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<CompanionTypeRelation>> {
    Ok(SelectedTypedRow::new(
        context.fragment,
        CompanionTypeRelation::new(context.semantic(row.get(0)?), context.semantic(row.get(1)?)),
    ))
}

fn decode_member_owner(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredMemberOwnerProperty>> {
    let member_name: String = row.get(3)?;
    let kind: String = row.get(4)?;
    let access: String = row.get(5)?;
    let compatibility: String = row.get(6)?;
    Ok(SelectedTypedRow::new(
        context.fragment,
        typed_rows::decode_member_owner_fields(
            context.semantic(row.get(0)?),
            context.semantic(row.get(1)?),
            context.node(row.get(2)?),
            &member_name,
            &kind,
            &access,
            &compatibility,
        ),
    ))
}

fn decode_deferred_member_owner(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredDeferredMemberOwner>> {
    let body: String = row.get(2)?;
    Ok(SelectedTypedRow::new(
        context.fragment,
        typed_rows::decode_deferred_member_owner(context, row.get(0)?, row.get(1)?, &body),
    ))
}

fn decode_supertype(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredSupertypeProperty>> {
    Ok(SelectedTypedRow::new(
        context.fragment,
        typed_rows::decode_supertype(
            context,
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
        )
        .into(),
    ))
}

fn decode_call_obligation(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredCallApplicabilityObligation>> {
    let arguments: String = row.get(6)?;
    let rules: String = row.get(7)?;
    let completion: Option<String> = row.get(8)?;
    let type_arguments: String = row.get(9)?;
    Ok(SelectedTypedRow::new(
        context.fragment,
        typed_rows::decode_call_obligation(
            context,
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            &arguments,
            &type_arguments,
            &rules,
            completion.as_deref(),
        ),
    ))
}

// ---------------------------------------------------------------------------
// Milestone 6 port block 4 (lane TF): every typed question below is answered
// from rows, one statement per blob per call.
// ---------------------------------------------------------------------------

/// One mount's share of a keyed typed read: the keys the request resolved to
/// inside that blob, in request order, deduplicated.
type MountKeys = (SelectedResolutionMountOrdinal, Vec<i64>);

impl<'selection, 'store> SelectedResolutionTypedSource<'selection, 'store> {
    /// Group one request's resolved coordinates by the blob that answers them.
    ///
    /// `semantic_coordinates` is unchanged: it is what turns a runtime
    /// identity into `(mount, key)` for a blob-local semantic and into
    /// `(mount, resolution_identities.id)` for a shared name through the one
    /// tier 1 membership family. What changes here is only what the key is
    /// then used for.
    fn local_keys_by_mount(
        &self,
        semantics: &[SemanticId],
        relation: TypedFactRelation,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<MountKeys>>> {
        self.keys_by_mount(semantics, relation, RequestKeySpace::Local, cancellation)
    }

    fn shared_keys_by_mount(
        &self,
        semantics: &[SemanticId],
        relation: TypedFactRelation,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<MountKeys>>> {
        self.keys_by_mount(semantics, relation, RequestKeySpace::Shared, cancellation)
    }

    fn keys_by_mount(
        &self,
        semantics: &[SemanticId],
        relation: TypedFactRelation,
        space: RequestKeySpace,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<MountKeys>>> {
        let Some(coordinates) = self.semantic_coordinates(semantics, relation, cancellation)?
        else {
            return Ok(None);
        };
        Ok(Some(group_keys(
            coordinates
                .into_iter()
                .filter(|coordinate| coordinate.space == space),
        )))
    }

    fn node_keys_by_mount(
        &self,
        nodes: &[BindingNodeId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<MountKeys>>> {
        let Some(coordinates) = self.node_coordinates(nodes, cancellation)? else {
            return Ok(None);
        };
        Ok(Some(group_keys(coordinates.into_iter())))
    }

    /// A selected source proof can close a gap used by a member property as
    /// well as by lexical or type-frontier completion. Keep the same proof on
    /// both keyed property reads, including staged rows.
    fn visit_open_property_gaps(
        &self,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDefinitionPropertyGap>>,
        read: impl FnOnce(
            &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDefinitionPropertyGap>>,
        ) -> StoreResult<TypedFactReadOutcome>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let maximum_rows = visitor.maximum_rows();
        let mut cancelled = false;
        let outcome = read(&mut TypedFactPageVisitor::with_maximum_rows(
            &mut |page: &[SelectedTypedRow<LoweredDefinitionPropertyGap>]| {
                let completions = page
                    .iter()
                    .map(|gap| {
                        ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnsupportedSemantic(
                                gap.row().reason_semantic(),
                            ),
                        ])
                    })
                    .collect::<Vec<_>>();
                let Some(closed) = super::resolution_stage::lexical_readers::close_completions(
                    self.selection,
                    &completions,
                    cancellation,
                )?
                else {
                    cancelled = true;
                    return Ok(false);
                };
                let open = page
                    .iter()
                    .zip(closed)
                    .filter(|(_, completion)| *completion != ResolutionCompletion::Complete)
                    .map(|(gap, _)| gap.clone())
                    .collect::<Vec<_>>();
                if open.is_empty() {
                    Ok(true)
                } else {
                    visitor.visit_page(&open)
                }
            },
            maximum_rows,
        ))?;
        if cancelled {
            Ok(TypedFactReadOutcome::cancelled(outcome.evidence().clone()))
        } else {
            Ok(outcome)
        }
    }

    /// Visit one request's selected local rows and matching staged rows.
    fn visit_local_and_staged_typed_rows<T: TypedRowEvidence + Clone>(
        &self,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, T>,
        local_mounts: impl FnOnce(&Self, &CancellationToken) -> StoreResult<Option<Vec<MountKeys>>>,
        sql: &str,
        decode: impl Fn(TypedRowContext, &Row<'_>) -> StoreResult<T>,
        stage: impl FnOnce(&mut TypedFactPageVisitor<'_, T>) -> StoreResult<TypedFactReadOutcome>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = local_mounts(self, cancellation)? else {
                    return cancelled();
                };
                self.visit_typed_rows(&mounts, sql, cancellation, visitor, decode)
            },
            stage,
        )
    }

    /// Read one typed question from rows: one statement per blob, its keys
    /// delivered as one JSON array, its rows decoded by one function and paged
    /// out in the order the statement produced them.
    fn visit_typed_rows<T: TypedRowEvidence>(
        &self,
        mounts: &[MountKeys],
        sql: &str,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, T>,
        decode: impl Fn(TypedRowContext, &Row<'_>) -> StoreResult<T>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let mut evidence = PolledCompletionAccumulator::new(cancellation);
        for (ordinal, keys) in mounts {
            let mount = &*self.mount(*ordinal)?;
            let key_array = json_array(keys.iter().copied());
            let Some(rows) = self.decode_page(
                mount,
                sql,
                &[&mount.blob_id() as &dyn rusqlite::ToSql, &key_array],
                cancellation,
                &decode,
                &mut evidence,
            )?
            else {
                return Ok(TypedFactReadOutcome::cancelled(
                    evidence.finish_semantic().0,
                ));
            };
            match Self::page_out(&rows, cancellation, visitor)? {
                PageOutcome::Exhausted => {}
                PageOutcome::Stopped => {
                    let (completion, cancelled) = evidence.finish_semantic();
                    return Ok(if cancelled {
                        TypedFactReadOutcome::cancelled(completion)
                    } else {
                        TypedFactReadOutcome::stopped(completion)
                    });
                }
                PageOutcome::Cancelled => {
                    return Ok(TypedFactReadOutcome::cancelled(
                        evidence.finish_semantic().0,
                    ));
                }
            }
        }
        Ok(if cancellation.is_cancelled() {
            TypedFactReadOutcome::cancelled(evidence.finish_semantic().0)
        } else {
            TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
        })
    }

    /// The same read with no key predicate: one statement per blob of a mount
    /// set the caller established.
    fn visit_typed_rows_in_mounts<T: TypedRowEvidence>(
        &self,
        mounts: &[SelectedResolutionMountOrdinal],
        sql: &str,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, T>,
        decode: impl Fn(TypedRowContext, &Row<'_>) -> StoreResult<T>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let mut evidence = PolledCompletionAccumulator::new(cancellation);
        for ordinal in mounts {
            let mount = &*self.mount(*ordinal)?;
            let Some(rows) = self.decode_page(
                mount,
                sql,
                &[&mount.blob_id() as &dyn rusqlite::ToSql],
                cancellation,
                &decode,
                &mut evidence,
            )?
            else {
                return Ok(TypedFactReadOutcome::cancelled(
                    evidence.finish_semantic().0,
                ));
            };
            match Self::page_out(&rows, cancellation, visitor)? {
                PageOutcome::Exhausted => {}
                PageOutcome::Stopped => {
                    let (completion, cancelled) = evidence.finish_semantic();
                    return Ok(if cancelled {
                        TypedFactReadOutcome::cancelled(completion)
                    } else {
                        TypedFactReadOutcome::stopped(completion)
                    });
                }
                PageOutcome::Cancelled => {
                    return Ok(TypedFactReadOutcome::cancelled(
                        evidence.finish_semantic().0,
                    ));
                }
            }
        }
        Ok(if cancellation.is_cancelled() {
            TypedFactReadOutcome::cancelled(evidence.finish_semantic().0)
        } else {
            TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
        })
    }

    /// One blob's rows for one statement, decoded.
    ///
    /// The whole answer for one blob lives for one call, which is the
    /// query-lifetime shape milestone 6 allows; nothing here outlives the
    /// request.
    fn decode_page<T: TypedRowEvidence>(
        &self,
        mount: &SelectedResolutionMountRecord,
        sql: &str,
        parameters: &[&dyn rusqlite::ToSql],
        cancellation: &CancellationToken,
        decode: &impl Fn(TypedRowContext, &Row<'_>) -> StoreResult<T>,
        evidence: &mut PolledCompletionAccumulator<'_>,
    ) -> StoreResult<Option<Vec<T>>> {
        let names = self
            .selection
            .shared_name_table()
            .interner(self.selection.connection());
        let context = TypedRowContext {
            fragment: mount.fragment_id(),
            ordinal: mount.ordinal().get(),
            language: mount.semantic_language(),
            names: &names,
        };
        self.read_statement(cancellation, |conn| {
            let mut statement = conn.prepare_cached(sql)?;
            let mut rows = statement.query(parameters)?;
            decode_typed_page(context, &mut rows, cancellation, decode, evidence)
        })
    }

    pub(in crate::analyzer::store) fn page_out<T>(
        rows: &[T],
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, T>,
    ) -> StoreResult<PageOutcome> {
        for page in rows.chunks(visitor.maximum_rows()) {
            if cancellation.is_cancelled() {
                return Ok(PageOutcome::Cancelled);
            }
            let keep_going = visitor.visit_page(page)?;
            if cancellation.is_cancelled() {
                return Ok(PageOutcome::Cancelled);
            }
            if !keep_going {
                return Ok(PageOutcome::Stopped);
            }
        }
        Ok(if cancellation.is_cancelled() {
            PageOutcome::Cancelled
        } else {
            PageOutcome::Exhausted
        })
    }
}

pub(in crate::analyzer::store) enum PageOutcome {
    Exhausted,
    Stopped,
    Cancelled,
}

/// Coordinates to one list of keys per mount, in mount order, each list in
/// request order and free of repeats.
fn group_keys(coordinates: impl Iterator<Item = RequestCoordinate>) -> Vec<MountKeys> {
    let mut grouped: Vec<MountKeys> = Vec::new();
    for coordinate in coordinates {
        match grouped
            .iter_mut()
            .find(|(ordinal, _)| *ordinal == coordinate.mount)
        {
            Some((_, keys)) => {
                if !keys.contains(&coordinate.keys[0]) {
                    keys.push(coordinate.keys[0]);
                }
            }
            None => grouped.push((coordinate.mount, vec![coordinate.keys[0]])),
        }
    }
    grouped
}

// Both arms answer one caller request. Preserve their row order and multiplicity;
// this buffer is dropped when that request finishes, before the next query.
fn visit_combined_typed_rows<T: TypedRowEvidence + Clone>(
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, T>,
    ordinary: impl FnOnce(&mut TypedFactPageVisitor<'_, T>) -> StoreResult<TypedFactReadOutcome>,
    stage: impl FnOnce(&mut TypedFactPageVisitor<'_, T>) -> StoreResult<TypedFactReadOutcome>,
) -> StoreResult<TypedFactReadOutcome> {
    let mut answer = Vec::new();
    let mut evidence = PolledCompletionAccumulator::new(cancellation);
    let ordinary = collect_typed_arm(&mut answer, &mut evidence, ordinary)?;
    if ordinary.is_cancelled() || cancellation.is_cancelled() {
        return Ok(TypedFactReadOutcome::cancelled(
            evidence.finish_semantic().0,
        ));
    }
    let stage = collect_typed_arm(&mut answer, &mut evidence, stage)?;
    if stage.is_cancelled() || cancellation.is_cancelled() {
        return Ok(TypedFactReadOutcome::cancelled(
            evidence.finish_semantic().0,
        ));
    }
    let terminal = SelectedResolutionTypedSource::page_out(&answer, cancellation, visitor)?;
    let (completion, cancelled) = evidence.finish_semantic();
    Ok(if cancelled || matches!(terminal, PageOutcome::Cancelled) {
        TypedFactReadOutcome::cancelled(completion)
    } else {
        match terminal {
            PageOutcome::Exhausted => {
                TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
            }
            PageOutcome::Stopped => TypedFactReadOutcome::stopped(completion),
            PageOutcome::Cancelled => unreachable!("handled cancelled terminal"),
        }
    })
}

fn collect_typed_arm<T: TypedRowEvidence + Clone>(
    answer: &mut Vec<T>,
    evidence: &mut PolledCompletionAccumulator<'_>,
    read: impl FnOnce(&mut TypedFactPageVisitor<'_, T>) -> StoreResult<TypedFactReadOutcome>,
) -> StoreResult<TypedFactReadOutcome> {
    let outcome = read(&mut TypedFactPageVisitor::new(&mut |page| {
        for row in page {
            row.include_evidence(evidence);
        }
        answer.extend_from_slice(page);
        Ok(true)
    }))?;
    // A cancelled decoder may have observed rows it could not hand to our
    // collector. Its terminal evidence retains that decoded prefix.
    evidence.include(outcome.evidence());
    assert!(
        outcome.is_exhausted() || outcome.is_cancelled(),
        "the collecting visitor never stops an arm"
    );
    Ok(outcome)
}

// Eager decoding makes every decoded row source-known, even if a caller stops
// on an earlier page. Keep that evidence across blobs until the read terminates.
#[doc(hidden)]
pub trait TypedRowEvidence {
    fn include_evidence(&self, _evidence: &mut PolledCompletionAccumulator<'_>) {}
}

macro_rules! no_typed_row_evidence {
    ($($row:ty),+ $(,)?) => { $(impl TypedRowEvidence for SelectedTypedRow<$row> {})+ };
}

no_typed_row_evidence!(
    LoweredRustReferenceContext,
    LoweredRustDeclarationAuthority,
    LoweredTypedFrontier,
    LoweredIntrinsicTypeDescriptor,
    LoweredBindingProjection,
    LoweredDeclarationTypeProperty,
    LoweredDeclarationVisibilityProperty,
    LoweredMemberScopeProperty,
    CompanionTypeRelation,
    JvmAliasProperty,
    LoweredMemberOwnerProperty,
    LoweredDeferredMemberOwner,
    LoweredConstructionRequirementProperty,
    LoweredSupertypeProperty,
);

impl TypedRowEvidence for SelectedTypedRow<LoweredTypeTransfer> {
    fn include_evidence(&self, evidence: &mut PolledCompletionAccumulator<'_>) {
        evidence.include(self.row().rule().completion());
    }
}

impl TypedRowEvidence for SelectedTypedRow<LoweredTypeComponent> {}
impl TypedRowEvidence for SelectedTypedRow<LoweredTypeProduction> {}
impl TypedRowEvidence for SelectedTypedRow<LoweredTypeArgument> {}
impl TypedRowEvidence for SelectedTypedRow<LoweredGenericTypeAliasParameter> {}
impl TypedRowEvidence for SelectedTypedRow<LoweredGenericFormal> {}

impl TypedRowEvidence for SelectedTypedRow<LoweredDeclaredTypeArgument> {}

impl TypedRowEvidence for SelectedTypedRow<LoweredUnderlyingType> {}

impl TypedRowEvidence for SelectedTypedRow<LoweredIntrinsicSeed> {
    fn include_evidence(&self, evidence: &mut PolledCompletionAccumulator<'_>) {
        evidence.include(self.row().frontier().completion());
    }
}

impl TypedRowEvidence for SelectedGapReasonProvenance {}
impl TypedRowEvidence for (SemanticId, SemanticId) {}
impl TypedRowEvidence for (i64, i64) {}

impl TypedRowEvidence for SelectedTypeFrontierCompletion {
    fn include_evidence(&self, evidence: &mut PolledCompletionAccumulator<'_>) {
        evidence.include(self.completion());
    }
}

impl TypedRowEvidence for SelectedQualifiedRoute {
    fn include_evidence(&self, evidence: &mut PolledCompletionAccumulator<'_>) {
        evidence.include_reason(ResolutionIncompleteReason::UnsupportedSemantic(
            self.row().coarse_gap_reason(),
        ));
    }
}

impl TypedRowEvidence for SelectedTypedRow<LoweredDefinitionPropertyGap> {
    fn include_evidence(&self, evidence: &mut PolledCompletionAccumulator<'_>) {
        evidence.include_reason(ResolutionIncompleteReason::UnsupportedSemantic(
            self.row().reason_semantic(),
        ));
    }
}

impl TypedRowEvidence for SelectedTypedRow<LoweredCallApplicabilityObligation> {
    fn include_evidence(&self, evidence: &mut PolledCompletionAccumulator<'_>) {
        evidence.include(self.row().completion());
    }
}

impl TypedRowEvidence for SelectedTypedRow<LoweredCallableSignatureProperty> {
    fn include_evidence(&self, evidence: &mut PolledCompletionAccumulator<'_>) {
        evidence.include(self.row().completion());
    }
}

fn decode_typed_page<T: TypedRowEvidence>(
    context: TypedRowContext,
    rows: &mut rusqlite::Rows<'_>,
    cancellation: &CancellationToken,
    decode: &impl Fn(TypedRowContext, &Row<'_>) -> StoreResult<T>,
    evidence: &mut PolledCompletionAccumulator<'_>,
) -> StoreResult<Option<Vec<T>>> {
    let mut decoded = Vec::new();
    while let Some(row) = rows.next()? {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let row = decode(context, row)?;
        row.include_evidence(evidence);
        decoded.push(row);
    }
    Ok(Some(decoded))
}

impl TypedRowEvidence for SelectedTypedRow<LoweredGenericFormalDefault> {}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod row_evidence_tests {
    use super::*;

    #[cfg(test)]
    use crate::analyzer::Language;

    #[cfg(test)]
    use crate::analyzer::resolution::LoweredTypedFragment;

    #[cfg(test)]
    use crate::analyzer::resolution::PreloadedFactResolutionService;

    use crate::analyzer::resolution::ResolutionSlotValue;
    use crate::analyzer::resolution::ResolutionTypeRef;
    use crate::analyzer::resolution::SharedNameId;
    use crate::analyzer::resolution::TypedFrontierState;

    use brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind;
    #[cfg(test)]
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeSlotRole;

    #[doc(hidden)]
    pub fn seed(context: TypedRowContext, slot: u32) -> SelectedTypedRow<LoweredIntrinsicSeed> {
        SelectedTypedRow::new(
            context.fragment,
            LoweredIntrinsicSeed::new(
                IntrinsicTypeKind::Primitive,
                "int",
                TypedFrontierState::new(
                    context.semantic(i64::from(slot)),
                    [ResolutionSlotValue::runtime(
                        ResolutionTypeRef::new(
                            SemanticId::shared_name(SharedNameId::interned(1)),
                            0,
                        ),
                        false,
                    )],
                    ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(
                            context.semantic(i64::from(slot + 100)),
                        ),
                    ]),
                ),
            ),
        )
    }

    #[cfg(test)]
    #[test]
    fn row_decode_and_preloaded_stop_preserve_the_same_observed_evidence() {
        let context = TypedRowContext {
            fragment: BindingFragmentId::for_test(b"row-evidence"),
            ordinal: 0,
            language: crate::analyzer::Language::Java,
            names: crate::analyzer::resolution::test_shared_names(),
        };
        let seed = seed(context, 1);
        let lowered = LoweredTypedFragment::new(
            context.fragment,
            Language::Java,
            vec![LoweredTypedFrontier::new(
                context.semantic(1),
                ResolutionTypeSlotRole::ExpressionValue,
            )],
            vec![],
            vec![seed.row().clone()],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
        );
        let empty = crate::analyzer::resolution::lower_for_test(
            context.fragment,
            Language::Java,
            &brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts::default(),
        );
        let service = PreloadedFactResolutionService::from_lowered_fragments(
            [empty.lexical().clone()],
            [lowered],
        );
        // Cancellation wins even when the callback also returns false.
        for (keep_going, cancel) in [(true, false), (false, false), (true, true), (false, true)] {
            let cancellation = CancellationToken::new();
            let mut expected_rows = Vec::new();
            let expected = service
                .visit_intrinsic_seed_pages_for_slots(
                    TypedFactRequest::new(&[context.semantic(1)]),
                    &cancellation,
                    &mut TypedFactPageVisitor::with_maximum_rows(
                        &mut |page| {
                            expected_rows.extend_from_slice(page);
                            if cancel {
                                cancellation.cancel();
                            }
                            Ok(keep_going)
                        },
                        1,
                    ),
                )
                .unwrap();
            let cancellation = CancellationToken::new();
            let mut evidence = PolledCompletionAccumulator::new(&cancellation);
            let conn = Connection::open_in_memory().unwrap();
            let mut statement = conn.prepare("SELECT 1").unwrap();
            let rows = decode_typed_page(
                context,
                &mut statement.query([]).unwrap(),
                &cancellation,
                &|_, _| Ok(seed.clone()),
                &mut evidence,
            )
            .unwrap()
            .unwrap();
            let mut actual_rows = Vec::new();
            let terminal = SelectedResolutionTypedSource::page_out(
                &rows,
                &cancellation,
                &mut TypedFactPageVisitor::with_maximum_rows(
                    &mut |page| {
                        actual_rows.extend_from_slice(page);
                        if cancel {
                            cancellation.cancel();
                        }
                        Ok(keep_going)
                    },
                    1,
                ),
            )
            .unwrap();
            let (completion, _) = evidence.finish_semantic();
            let actual = match terminal {
                PageOutcome::Exhausted => {
                    TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
                }
                PageOutcome::Stopped => TypedFactReadOutcome::stopped(completion),
                PageOutcome::Cancelled => TypedFactReadOutcome::cancelled(completion),
            };
            assert_eq!(actual_rows, expected_rows);
            assert_eq!(actual.terminal(), expected.terminal());
            assert_eq!(actual.evidence(), expected.evidence());
        }
    }
}
