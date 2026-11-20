//! Sparse authored modifiers use the same selected authority as typed rows.
use super::*;
use crate::analyzer::resolution::fact_source::SelectedDeclarationModifier;

#[derive(Clone, Copy)]
pub(in crate::analyzer::store) enum ResolvedReceiverProofQuestion {
    OwnerApplication {
        application: SemanticId,
    },
    CurrentInstanceTransfer {
        application: SemanticId,
        receiver: SemanticId,
        transfer_rule: SemanticId,
    },
    BaseReceiverContext {
        reference: SemanticId,
    },
}

impl SelectedResolutionTypedSource<'_, '_> {
    pub(super) fn visit_declaration_modifiers(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<SelectedDeclarationModifier>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let mut requests =
            std::collections::BTreeMap::<SelectedResolutionMountOrdinal, Vec<i64>>::new();
        for &definition in definitions.as_slice() {
            let Some(Some(SelectedSemanticProvenance::FragmentLocal(local))) = self
                .authority
                .semantic_catalog_provenance(definition, cancellation)?
            else {
                return cancelled();
            };
            requests
                .entry(local.mount().ordinal())
                .or_default()
                .push(local.local_key().get());
        }
        for (ordinal, mut keys) in requests {
            keys.sort_unstable();
            keys.dedup();
            let mount = self.mount(ordinal)?;
            let Some(rows) = self.authority.read_authority(&mount, cancellation, |connection| {
                let keys = serde_json::to_string(&keys).expect("modifier request keys");
                let mut statement = connection.prepare_cached(
                    "SELECT modifiers.definition,modifiers.partial FROM json_each(?1) AS requested CROSS JOIN resolution_declaration_modifiers AS modifiers WHERE modifiers.blob_id=?2 AND modifiers.definition=requested.value ORDER BY modifiers.definition"
                )?;
                let mut cursor = statement.query(rusqlite::params![keys, mount.blob_id()])?;
                let mut rows = Vec::new();
                while let Some(row) = cursor.next()? {
                    if cancellation.is_cancelled() { return Ok(None); }
                    rows.push(SelectedTypedRow::new(mount.fragment_id(), SelectedDeclarationModifier {
                        definition: SemanticId::local(ordinal.get(), row.get(0)?), partial: row.get(1)?,
                    }));
                }
                Ok(Some(rows))
            })? else { return cancelled(); };
            let Some(rows) = rows else {
                return cancelled();
            };
            for page in rows.chunks(PAGE_ROWS) {
                let keep_going = visitor.visit_page(page)?;
                if cancellation.is_cancelled() {
                    return cancelled();
                }
                if !keep_going {
                    return Ok(TypedFactReadOutcome::stopped(
                        ResolutionCompletion::Complete,
                    ));
                }
            }
        }
        if cancellation.is_cancelled() {
            return cancelled();
        }
        Ok(
            TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
                .with_inventory_evidence(
                crate::analyzer::resolution::fact_source::TypedFactInventoryEvidence::Established(
                    ResolutionCompletion::Complete,
                ),
            ),
        )
    }
}

impl SelectedResolutionTypedSource<'_, '_> {
    /// Read the exact selected blob key through the existing authority gate.
    /// Consumers retain their own normal File or proof receipt; this helper
    /// does not manufacture an unrelated lookup payload.
    pub(super) fn selected_source_blob_key(
        &self,
        mount: &super::super::resolution_selection::SelectedResolutionMountRecord,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<brokk_bifrost_core::gitblob::BlobKey>> {
        use brokk_bifrost_core::gitblob::{BlobKey, ParseVariant};
        let Some(variant) = self
            .authority
            .read_authority(mount, cancellation, |connection| {
                Ok(connection.query_row(
                    "SELECT parse_variant FROM blobs WHERE id=?1",
                    [mount.blob_id()],
                    |row| row.get::<_, Vec<u8>>(0),
                )?)
            })?
        else {
            return Ok(None);
        };
        let variant = match variant.as_slice() {
            [] => ParseVariant::Empty,
            bytes if bytes.len() == 32 => {
                ParseVariant::Digest(bytes.try_into().expect("checked variant length"))
            }
            _ => {
                return Err(StoreError::new(
                    "selected receiver proof has an invalid parse variant",
                ));
            }
        };
        Ok(Some(BlobKey {
            oid: mount.blob_oid(),
            lang: mount.storage_language().to_owned(),
            variant,
        }))
    }

    pub(in crate::analyzer::store) fn receiver_proof_source(
        &self,
        mount: &super::super::resolution_selection::SelectedResolutionMountRecord,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<crate::analyzer::semantic::read_ledger::SelectedProofSource>> {
        use crate::analyzer::semantic::read_ledger::{SelectedProofSource, StoredParseVariant};
        let Some(key) = self.selected_source_blob_key(mount, cancellation)? else {
            return Ok(None);
        };
        let parse_variant = match key.variant {
            brokk_bifrost_core::gitblob::ParseVariant::Empty => StoredParseVariant::Empty,
            brokk_bifrost_core::gitblob::ParseVariant::Digest(digest) => {
                StoredParseVariant::Digest(digest)
            }
        };
        Ok(Some(SelectedProofSource {
            storage_language: mount.storage_language().into(),
            rel_path: mount.persisted_relative_path().into(),
            blob_oid: key
                .oid
                .as_bytes()
                .try_into()
                .expect("object ID has 20 bytes"),
            parse_variant,
            producer_epoch: mount.producer_epoch().into(),
        }))
    }

    pub(super) fn base_receiver_context_question(
        &self,
        reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<crate::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion>>
    {
        use crate::analyzer::semantic::read_ledger::{
            LocalResolutionIdentityDigest, SelectedReceiverProofQuestion,
        };
        if !self.validate_selected_interiors(cancellation)? {
            return Ok(None);
        }
        let Some(Some(SelectedSemanticProvenance::FragmentLocal(local))) = self
            .authority
            .semantic_catalog_provenance(reference, cancellation)?
        else {
            return Ok(None);
        };
        let mount = self.mount(local.mount().ordinal())?;
        let Some(source) = self.receiver_proof_source(&mount, cancellation)? else {
            return Ok(None);
        };
        Ok(Some(SelectedReceiverProofQuestion::BaseReceiverContext {
            source,
            reference: LocalResolutionIdentityDigest::new(local.identity().fragment_local_digest()),
        }))
    }

    pub(super) fn receiver_proof_question(
        &self,
        application: SemanticId,
        transfer: Option<(SemanticId, SemanticId)>,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<crate::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion>>
    {
        use crate::analyzer::semantic::read_ledger::{
            LocalResolutionIdentityDigest, SelectedReceiverProofQuestion,
        };
        if !self.validate_selected_interiors(cancellation)? {
            return Ok(None);
        }
        let Some(Some(SelectedSemanticProvenance::FragmentLocal(app))) = self
            .authority
            .semantic_catalog_provenance(application, cancellation)?
        else {
            return Ok(None);
        };
        let mount = self.mount(app.mount().ordinal())?;
        let Some(source) = self.receiver_proof_source(&mount, cancellation)? else {
            return Ok(None);
        };
        let application =
            LocalResolutionIdentityDigest::new(app.identity().fragment_local_digest());
        let question = if let Some((receiver, rule)) = transfer {
            let Some(Some(SelectedSemanticProvenance::FragmentLocal(receiver))) = self
                .authority
                .semantic_catalog_provenance(receiver, cancellation)?
            else {
                return Ok(None);
            };
            let Some(Some(SelectedSemanticProvenance::FragmentLocal(rule))) = self
                .authority
                .semantic_catalog_provenance(rule, cancellation)?
            else {
                return Ok(None);
            };
            if receiver.mount() != app.mount() || rule.mount() != app.mount() {
                return Ok(None);
            }
            SelectedReceiverProofQuestion::CurrentInstanceTransfer {
                source,
                application,
                receiver: LocalResolutionIdentityDigest::new(
                    receiver.identity().fragment_local_digest(),
                ),
                transfer_rule: LocalResolutionIdentityDigest::new(
                    rule.identity().fragment_local_digest(),
                ),
            }
        } else {
            SelectedReceiverProofQuestion::OwnerApplication {
                source,
                application,
            }
        };
        Ok(Some(question))
    }

    pub(in crate::analyzer::store) fn resolve_receiver_proof_question(
        &self,
        question: &crate::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<ResolvedReceiverProofQuestion>> {
        use crate::analyzer::resolution::ResolutionSemanticIdentity;
        use crate::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion;
        if !self.validate_selected_interiors(cancellation)? {
            return Ok(None);
        }
        let source = question.source();
        let Some(mount) = self
            .selection
            .mount_record_for_path(&source.storage_language, &source.rel_path)?
        else {
            return Ok(None);
        };
        if self.receiver_proof_source(&mount, cancellation)?.as_ref() != Some(source) {
            return Ok(None);
        }
        let resolve =
            |digest: &crate::analyzer::semantic::read_ledger::LocalResolutionIdentityDigest| {
                self.authority.semantic_for_identity(
                    &mount,
                    ResolutionSemanticIdentity::fragment_local(*digest.as_bytes()),
                    cancellation,
                )
            };
        let resolved = match question {
            SelectedReceiverProofQuestion::OwnerApplication { application, .. } => {
                let Some(Some(application)) = resolve(application)? else {
                    return Ok(None);
                };
                ResolvedReceiverProofQuestion::OwnerApplication { application }
            }
            SelectedReceiverProofQuestion::CurrentInstanceTransfer {
                application,
                receiver,
                transfer_rule,
                ..
            } => {
                let Some(Some(application)) = resolve(application)? else {
                    return Ok(None);
                };
                let Some(Some(receiver)) = resolve(receiver)? else {
                    return Ok(None);
                };
                let Some(Some(transfer_rule)) = resolve(transfer_rule)? else {
                    return Ok(None);
                };
                ResolvedReceiverProofQuestion::CurrentInstanceTransfer {
                    application,
                    receiver,
                    transfer_rule,
                }
            }
            SelectedReceiverProofQuestion::BaseReceiverContext { reference, .. } => {
                let Some(Some(reference)) = resolve(reference)? else {
                    return Ok(None);
                };
                ResolvedReceiverProofQuestion::BaseReceiverContext { reference }
            }
        };
        // Reconstruct through the same ordinary catalog authority as the fill.
        let current = match resolved {
            ResolvedReceiverProofQuestion::OwnerApplication { application } => {
                self.receiver_proof_question(application, None, cancellation)?
            }
            ResolvedReceiverProofQuestion::CurrentInstanceTransfer {
                application,
                receiver,
                transfer_rule,
            } => self.receiver_proof_question(
                application,
                Some((receiver, transfer_rule)),
                cancellation,
            )?,
            ResolvedReceiverProofQuestion::BaseReceiverContext { reference } => {
                self.base_receiver_context_question(reference, cancellation)?
            }
        };
        if current.as_ref() != Some(question) {
            return Ok(None);
        }
        Ok(Some(resolved))
    }
}
