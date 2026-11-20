//! Canonical selected source inputs for normal declaration access. No access
//! language rules, source scans or alternative identity ledger live here.
use super::*;
use crate::analyzer::resolution::fact_source::{
    SelectedAccessDeclaration, SelectedAccessReference, SelectedAccessSource,
};
use crate::analyzer::resolution::{
    BatchResolutionFragmentSource, ResolutionLocalKey, ResolutionQuery, SelectedSemanticProvenance,
};
use crate::analyzer::store::resolution_operation::SelectedSourceFileCertificate;
use crate::analyzer::store::selected_definition::{
    SelectedDeclarationDefinition, SelectedDefinitionUnitReadOutcome,
    SelectedLexicalDefinitionReadOutcome,
};

fn established_access_inventory(outcome: TypedFactReadOutcome) -> bool {
    outcome.is_exhausted()
        && matches!(
            outcome.inventory_evidence(),
            TypedFactInventoryEvidence::Established(ResolutionCompletion::Complete)
        )
        && outcome.into_parts().1 == ResolutionCompletion::Complete
}

impl SelectedResolutionTypedSource<'_, '_> {
    fn access_source_coordinate(
        &self,
        semantic: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<(SelectedResolutionMountOrdinal, ResolutionLocalKey)>> {
        if cancellation.is_cancelled() || !self.validate_selected_interiors(cancellation)? {
            return Ok(None);
        }
        let lexical =
            super::super::resolution_lexical::SelectedResolutionLexicalSource::new_on_demand(
                self.selection,
            );
        let Some(provenance) = lexical.semantic_provenance(semantic, cancellation)? else {
            return Ok(None);
        };
        Ok(match provenance {
            SelectedSemanticProvenance::FragmentLocal(local)
                if (local.mount().ordinal().get() as usize)
                    < self.selection.persisted_mount_count() =>
            {
                Some((local.mount().ordinal(), local.local_key()))
            }
            _ => None,
        })
    }

    fn certify_access_source(
        &self,
        ordinal: SelectedResolutionMountOrdinal,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<(crate::analyzer::ProjectFile, Language)>> {
        let (Some(root), Some(services)) = (self.source_project_root, self.receiver_proof_services)
        else {
            return Ok(None);
        };
        let mount = self.mount(ordinal)?;
        let file = crate::analyzer::ProjectFile::new(
            root,
            std::path::PathBuf::from(mount.persisted_relative_path()),
        );
        let Some(key) = self.selected_source_blob_key(&mount, cancellation)? else {
            return Ok(None);
        };
        // The mount's validated producer, blob and configured variant all
        // describe the same selected source. Keep this read outside the
        // verified-declaration capture replacement, including on denied paths.
        if !services.certify_selected_source_file(&SelectedSourceFileCertificate {
            file: &file,
            oid: key.oid,
            parse_variant: key.variant,
            producer_epoch: mount.producer_epoch(),
        }) {
            return Ok(None);
        }
        Ok(Some((file, mount.semantic_language())))
    }

    pub(super) fn read_access_reference(
        &self,
        reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<SelectedAccessReference>> {
        let Some((ordinal, _)) = self.access_source_coordinate(reference, cancellation)? else {
            return Ok(None);
        };
        let Some((file, language)) = self.certify_access_source(ordinal, cancellation)? else {
            return Ok(None);
        };
        let lexical =
            super::super::resolution_lexical::SelectedResolutionLexicalSource::new_on_demand(
                self.selection,
            );
        let rows =
            lexical.lookup_reference_seeds(&[ResolutionQuery::new(reference)], cancellation)?;
        if !rows.is_exhausted()
            || rows.evidence() != &ResolutionCompletion::Complete
            || rows.rows().len() != 1
            || cancellation.is_cancelled()
        {
            return Ok(None);
        }
        let Some(seed) = rows.rows().first().and_then(|row| row.seed()) else {
            return Ok(None);
        };
        // Ownership is affirmative parser metadata, independent of semantic
        // access/applicability gaps on this seed. Those gaps remain on the
        // original path; they do not turn owner_known=0 into OutsideType.
        if seed.reference() != reference {
            return Ok(None);
        }
        let Some(metadata) = seed.site_metadata() else {
            return Ok(None);
        };
        Ok(Some(SelectedAccessReference {
            source: SelectedAccessSource {
                file,
                language,
                start_byte: metadata.start_byte(),
                end_byte: metadata.end_byte(),
            },
            owner: metadata.reference_owner(),
        }))
    }

    pub(super) fn read_access_declaration(
        &self,
        definition: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<SelectedAccessDeclaration>> {
        let Some(coordinate @ (ordinal, key)) =
            self.access_source_coordinate(definition, cancellation)?
        else {
            return Ok(None);
        };
        let Some((file, language)) = self.certify_access_source(ordinal, cancellation)? else {
            return Ok(None);
        };
        let SelectedLexicalDefinitionReadOutcome::Ready(spans) = self
            .selection
            .selected_lexical_definitions(&[coordinate], cancellation)?
        else {
            return Ok(None);
        };
        let [(_, _, span)] = spans.as_slice() else {
            return Ok(None);
        };
        let range = match span {
            SelectedDeclarationDefinition::Lexical(lexical) => lexical.declaration_range,
            SelectedDeclarationDefinition::WithoutUnit(range)
            | SelectedDeclarationDefinition::Module(range) => *range,
        };
        if let SelectedDeclarationDefinition::Lexical(lexical) = span {
            return Ok(Some(SelectedAccessDeclaration {
                source: SelectedAccessSource {
                    file,
                    language,
                    start_byte: range.start_byte,
                    end_byte: range.end_byte,
                },
                lexical_kind: Some(lexical.kind),
                partial: None,
                is_type: false,
                ordinary_owner: None,
                visibility: None,
            }));
        }
        let SelectedDefinitionUnitReadOutcome::Ready(units) = self
            .selection
            .selected_declaration_units(&[coordinate], cancellation)?
        else {
            return Ok(None);
        };
        let [(_, _, unit)] = units.as_ref() else {
            return Ok(None);
        };
        if unit.flags.synthetic {
            return Ok(None);
        }
        let mounts = vec![(ordinal, vec![key.get()])];
        let mut owners = Vec::new();
        let mut collect = |rows: &[SelectedTypedRow<LoweredMemberOwnerProperty>]| {
            owners.extend(rows.iter().cloned());
            Ok(true)
        };
        let outcome = self.visit_typed_rows(
            &mounts,
            typed_rows::MEMBER_OWNERS_BY_DEFINITION_SQL,
            cancellation,
            &mut TypedFactPageVisitor::new(&mut collect),
            decode_member_owner,
        )?;
        if !established_access_inventory(outcome) {
            return Ok(None);
        }
        let ordinary_owner = match owners.as_slice() {
            [] => Some(None),
            [owner] => Some(Some(owner.row().owner_definition())),
            _ => None,
        };
        let mut scopes = Vec::new();
        let mut collect = |rows: &[SelectedTypedRow<LoweredMemberScopeProperty>]| {
            scopes.extend(rows.iter().cloned());
            Ok(true)
        };
        let outcome = self.visit_typed_rows(
            &mounts,
            typed_rows::MEMBER_SCOPES_BY_DEFINITION_SQL,
            cancellation,
            &mut TypedFactPageVisitor::new(&mut collect),
            decode_member_scope,
        )?;
        if !established_access_inventory(outcome) {
            return Ok(None);
        }
        let is_type = matches!(scopes.as_slice(), [scope] if scope.row().scope_kind() == brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeKind::TypeBody);
        let mut visibility = Vec::new();
        let mut collect = |rows: &[SelectedTypedRow<LoweredDeclarationVisibilityProperty>]| {
            visibility.extend(rows.iter().cloned());
            Ok(true)
        };
        let outcome = self.visit_typed_rows(
            &mounts,
            typed_rows::DECLARATION_VISIBILITIES_BY_DEFINITION_SQL,
            cancellation,
            &mut TypedFactPageVisitor::new(&mut collect),
            decode_declaration_visibility,
        )?;
        if !established_access_inventory(outcome) {
            return Ok(None);
        }
        let visibility = match visibility.as_slice() {
            [row] => Some(row.row().visibility()),
            _ => None,
        };
        let Some(facts) = self.declaration_source_facts(definition, cancellation)? else {
            return Ok(None);
        };
        Ok(Some(SelectedAccessDeclaration {
            source: SelectedAccessSource {
                file,
                language,
                start_byte: range.start_byte,
                end_byte: range.end_byte,
            },
            lexical_kind: None,
            partial: facts.partial,
            is_type,
            ordinary_owner,
            visibility,
        }))
    }
}
