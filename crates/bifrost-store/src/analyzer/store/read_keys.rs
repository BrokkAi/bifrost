//! Lossless analyzer-store columns for one recorded [`ReadKey`].
//!
//! Persisted derived products use the same read vocabulary and must rebuild
//! the exact structured key before verification. Keeping that encoding here
//! makes adding a new [`ReadKey`] variant an exhaustive-match compile error for
//! every store client instead of letting two product tables drift.

use brokk_bifrost_core::analyzer::structural::kinds::Role;
use brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationQuestion;
use brokk_bifrost_semantic::analyzer::semantic::read_ledger::{
    FactSubject, PersistedDerivationFamily, WorkspaceFactFamily,
};
use git2::Oid;

use super::{Result, StoreError};
use crate::analyzer::content_identity::WorkspaceContentIdentity;
use crate::analyzer::invalidation::{DerivedArtifactId, DerivedArtifactKind};
use crate::analyzer::read_ledger::{
    CallSiteLocator, IndexFamily, LookupKind, LookupQuestion, ReadKey,
};
use crate::analyzer::semantic::ids::StableDigest;
use crate::analyzer::{CodeUnitType, Language};
use brokk_bifrost_semantic::analyzer::semantic::read_ledger::{
    StoredSemanticIrParseVariant, StoredSemanticIrPublicationQuestion,
};

/// The normalized column values for one [`ReadKey`].
///
/// Clients persist these fields in this order and select them in the order
/// accepted by [`decode_read_key`]. Optional columns stay typed rather than
/// being folded into an opaque payload because SQLite can inspect and index
/// the structured questions later.
pub(super) struct ReadKeyColumns {
    pub(super) key_digest: [u8; 32],
    pub(super) kind: &'static str,
    pub(super) family: Option<&'static str>,
    pub(super) languages: Option<String>,
    pub(super) rel_path: Option<String>,
    pub(super) name: Option<String>,
    pub(super) structural_role: Option<&'static str>,
    pub(super) structural_keyword: Option<i64>,
    pub(super) index_key: Option<Vec<u8>>,
    pub(super) blob_oid: Option<String>,
    pub(super) subject: Option<Vec<u8>>,
    pub(super) start_byte: Option<i64>,
    pub(super) end_byte: Option<i64>,
    pub(super) digest: Option<Vec<u8>>,
    pub(super) site_ordinal: Option<i64>,
    pub(super) decl_kind: Option<&'static str>,
    pub(super) decl_signature: Option<String>,
    pub(super) workspace_fact_family: Option<&'static str>,
    pub(super) fact_member: Option<String>,
    pub(super) fact_names: Option<String>,
    pub(super) copy_owning_unit: Option<Vec<u8>>,
    pub(super) copy_target_unit: Option<Vec<u8>>,
    pub(super) copy_module_path: Option<String>,
    pub(super) copy_target_identity_digest: Option<Vec<u8>>,
    pub(super) copy_census_version: Option<i64>,
    pub(super) copy_config_digest: Option<Vec<u8>>,
    pub(super) copy_producer_digest: Option<Vec<u8>>,
    pub(super) parse_variant_kind: Option<&'static str>,
    pub(super) parse_variant_digest: Option<Vec<u8>>,
}

impl ReadKeyColumns {
    /// Encode one key by exhaustively projecting its structured fields.
    /// A memory-only key (`ReadKey::is_persistable`) is refused with an
    /// error: publication gates check it first, and this keeps a missed
    /// gate from writing a key that replay cannot serve.
    pub(super) fn of(key: &ReadKey) -> Result<Self> {
        if !key.is_persistable() {
            return Err(StoreError::new(format!(
                "a memory-only read key cannot be persisted: {key:?}"
            )));
        }
        let mut columns = Self {
            key_digest: *key.canonical_digest().as_bytes(),
            kind: key.stable_label(),
            family: None,
            languages: None,
            rel_path: None,
            name: None,
            structural_role: None,
            structural_keyword: None,
            index_key: None,
            blob_oid: None,
            subject: None,
            start_byte: None,
            end_byte: None,
            digest: None,
            site_ordinal: None,
            decl_kind: None,
            decl_signature: None,
            workspace_fact_family: None,
            fact_member: None,
            fact_names: None,
            copy_owning_unit: None,
            copy_target_unit: None,
            copy_module_path: None,
            copy_target_identity_digest: None,
            copy_census_version: None,
            copy_config_digest: None,
            copy_producer_digest: None,
            parse_variant_kind: None,
            parse_variant_digest: None,
        };
        match key {
            ReadKey::File {
                language,
                rel_path,
                blob,
                parse_variant,
            } => {
                columns.languages = Some(language.config_label().to_string());
                columns.rel_path = Some(rel_path.to_string());
                columns.blob_oid = Some(blob.to_string());
                // For File keys, digest holds the parse variant; NULL means Empty.
                columns.digest = parse_variant.file_read_key_field().map(<[u8]>::to_vec);
            }
            ReadKey::PathAbsent { language, rel_path } => {
                columns.languages = Some(language.config_label().to_string());
                columns.rel_path = Some(rel_path.to_string());
            }
            ReadKey::Index { family, key } => {
                columns.family = Some(family.stable_label());
                columns.index_key = Some(key.to_vec());
            }
            ReadKey::Lookup {
                kind,
                question,
                digest,
            } => {
                assert!(
                    lookup_question_matches_kind(*kind, question),
                    "a lookup kind must use its supported question shape"
                );
                columns.family = Some(kind.stable_label());
                columns.digest = Some(digest.as_bytes().to_vec());
                match question {
                    LookupQuestion::CertifiedDefinition { .. } => {
                        unreachable!(
                            "a certified definition key is not persisted until #10325 adds its schema with a migration"
                        )
                    }
                    LookupQuestion::StoredSemanticIrPublication(question) => {
                        columns.languages = Some(question.storage_language.to_string());
                        columns.rel_path = Some(question.rel_path.to_string());
                        columns.subject = Some(question.subject.to_vec());
                        match question.parse_variant {
                            StoredSemanticIrParseVariant::Empty => {
                                columns.parse_variant_kind = Some("empty")
                            }
                            StoredSemanticIrParseVariant::Digest(digest) => {
                                columns.parse_variant_kind = Some("digest");
                                columns.parse_variant_digest = Some(digest.to_vec());
                            }
                        }
                    }
                    LookupQuestion::Derivation(question) => {
                        let LookupKind::Derivation(id) = kind else {
                            unreachable!()
                        };
                        let family = PersistedDerivationFamily::of(id.0)
                            .expect("unregistered persisted derivation family");
                        assert!(
                            family.admits(question),
                            "invalid persisted derivation question"
                        );
                        columns.languages = question
                            .language
                            .map(|language| language.config_label().to_string());
                        columns.subject = question.subject.map(|subject| subject.to_vec());
                        columns.rel_path = question.rel_path.as_deref().map(str::to_owned);
                        columns.name = question.name.as_deref().map(str::to_owned);
                    }
                    LookupQuestion::RustCopyAbsence {
                        owning_unit,
                        target_unit,
                        module_path,
                        target_identity_digest,
                        census_version,
                        config_digest,
                        producer_digest,
                    } => {
                        columns.copy_owning_unit = Some(owning_unit.as_bytes().to_vec());
                        columns.copy_target_unit = Some(target_unit.as_bytes().to_vec());
                        columns.copy_module_path = Some(module_path.to_string());
                        columns.copy_target_identity_digest =
                            Some(target_identity_digest.as_bytes().to_vec());
                        columns.copy_census_version = Some(i64::from(*census_version));
                        columns.copy_config_digest = Some(config_digest.as_bytes().to_vec());
                        columns.copy_producer_digest = Some(producer_digest.as_bytes().to_vec());
                    }
                    LookupQuestion::StructuralName {
                        language,
                        name,
                        authority,
                    } => {
                        columns.languages = Some(language.config_label().to_string());
                        columns.name = Some(name.to_string());
                        columns.subject = Some(authority.as_bytes().to_vec());
                    }
                    LookupQuestion::StructuralRoleName {
                        language,
                        role,
                        name,
                        keyword,
                        authority,
                    } => {
                        columns.languages = Some(language.config_label().to_string());
                        columns.name = Some(name.to_string());
                        columns.subject = Some(authority.as_bytes().to_vec());
                        columns.structural_role = Some(role.label());
                        columns.structural_keyword = Some(i64::from(*keyword));
                    }
                    LookupQuestion::StructuralRecovered {
                        language,
                        authority,
                    } => {
                        columns.languages = Some(language.config_label().to_string());
                        columns.subject = Some(authority.as_bytes().to_vec());
                    }
                    LookupQuestion::Name { language, name } => {
                        columns.languages =
                            language.map(|language| language.config_label().to_string());
                        columns.name = Some(name.to_string());
                    }
                    LookupQuestion::RustPlacedDeclaration {
                        blob,
                        declaration,
                        rel_path,
                    } => {
                        columns.languages = Some("rust".into());
                        columns.blob_oid = Some(Oid::from_bytes(blob)?.to_string());
                        columns.rel_path = Some(rel_path.to_string());
                        columns.start_byte = Some(i64::from(*declaration));
                        columns.end_byte = Some(i64::from(*declaration));
                    }
                    LookupQuestion::Declaration {
                        rel_path,
                        fq_name,
                        kind,
                        signature,
                    } => {
                        columns.rel_path = Some(rel_path.to_string());
                        columns.name = Some(fq_name.to_string());
                        columns.decl_kind = Some(kind.identity_label());
                        columns.decl_signature = signature.clone();
                    }
                    LookupQuestion::File { rel_path } => {
                        columns.rel_path = Some(rel_path.to_string());
                    }
                    LookupQuestion::CallSite {
                        rel_path,
                        procedure,
                        site,
                    } => {
                        columns.rel_path = Some(rel_path.to_string());
                        columns.subject = Some(procedure.as_bytes().to_vec());
                        // Legacy interval columns now hold a scalar source-order rank.
                        // Keeping the SQL layout also preserves existing plan families.
                        columns.start_byte = Some(site.ordinal as i64);
                        columns.end_byte = Some(site.ordinal as i64);
                        if *kind == LookupKind::ProcedureDispatch {
                            columns.site_ordinal = Some(site.ordinal as i64);
                        }
                    }
                    LookupQuestion::WorkspaceFact {
                        family,
                        language,
                        subject,
                    } => {
                        columns.workspace_fact_family = Some(family.stable_label());
                        columns.languages = Some(language.config_label().to_string());
                        match subject {
                            FactSubject::Whole => {}
                            FactSubject::Class { class } => {
                                columns.subject = Some(class.as_bytes().to_vec())
                            }
                            FactSubject::File { rel_path } => {
                                columns.rel_path = Some(rel_path.to_string())
                            }
                            FactSubject::Named { name } => columns.name = Some(name.to_string()),
                            FactSubject::NamedMember { owner, member } => {
                                columns.name = Some(owner.to_string());
                                columns.fact_member = Some(member.to_string());
                            }
                            FactSubject::ClassMember { class, member } => {
                                columns.subject = Some(class.as_bytes().to_vec());
                                columns.fact_member = Some(member.to_string());
                            }
                            FactSubject::NameGroupMember { names, member } => {
                                columns.fact_names = Some(
                                    serde_json::to_string(names)
                                        .expect("qualified names serialize"),
                                );
                                columns.fact_member = Some(member.to_string());
                            }
                            FactSubject::FileNamedMember {
                                rel_path,
                                owner,
                                member,
                                environment,
                            } => {
                                columns.rel_path = Some(rel_path.to_string());
                                columns.name = Some(owner.to_string());
                                columns.fact_member = Some(member.to_string());
                                columns.subject =
                                    environment.map(|digest| digest.as_bytes().to_vec());
                            }
                        }
                    }
                    LookupQuestion::Summary { identity } => {
                        columns.subject = Some(identity.as_bytes().to_vec());
                    }
                    LookupQuestion::ExternalSelection { question_digest } => {
                        columns.subject = Some(question_digest.to_vec());
                    }
                }
            }
            ReadKey::Artifact { id, rel_path } => {
                columns.family = Some(id.kind().stable_label());
                columns.subject = Some(id.fingerprint().as_bytes().to_vec());
                columns.rel_path = rel_path.as_ref().map(ToString::to_string);
            }
            ReadKey::Scope {
                languages,
                identity,
            } => {
                columns.languages = Some(language_list(languages));
                columns.digest = Some(identity.digest().as_bytes().to_vec());
            }
            ReadKey::Models(digest) | ReadKey::Configuration(digest) | ReadKey::Epoch(digest) => {
                columns.digest = Some(digest.as_bytes().to_vec());
            }
            ReadKey::Policy {
                semantic_hash,
                source,
            } => {
                columns.subject = Some(semantic_hash.as_bytes().to_vec());
                columns.digest = Some(source.as_bytes().to_vec());
            }
        }
        Ok(columns)
    }
}

/// Rebuild one read key from normalized columns and verify its stored digest.
///
/// `row` must select `key_digest`, `kind`, `family`, `languages`, `rel_path`,
/// `name`, `index_key`, `blob_oid`, `subject`, `start_byte`, `end_byte`,
/// `digest`, `site_ordinal`, `decl_kind`, `decl_signature`, and
/// `workspace_fact_family`, `fact_member`, `fact_names`, in that order.
/// Comparing the rebuilt key's canonical digest with `key_digest` turns column
/// fidelity into a checked store invariant.
pub(super) fn decode_read_key(row: &rusqlite::Row<'_>) -> Result<ReadKey> {
    let key_digest = row.get::<_, Vec<u8>>(0)?;
    let kind = row.get::<_, String>(1)?;
    let family = row.get::<_, Option<String>>(2)?;
    let languages = row.get::<_, Option<String>>(3)?;
    let rel_path = row.get::<_, Option<String>>(4)?;
    let name = row.get::<_, Option<String>>(5)?;
    let has_role_projection = row.as_ref().column_names().get(27) == Some(&"structural_role");
    if has_role_projection && row.as_ref().column_count() < 29 {
        return Err(StoreError::corrupt("partial structural role projection"));
    }
    let structural_role = has_role_projection
        .then(|| row.get::<_, Option<String>>(27))
        .transpose()?
        .flatten();
    let structural_keyword = has_role_projection
        .then(|| row.get::<_, Option<i64>>(28))
        .transpose()?
        .flatten();
    let is_role_name =
        kind == "lookup" && family.as_deref() == Some("structural_role_name_inventory");
    if !is_role_name && (structural_role.is_some() || structural_keyword.is_some()) {
        return Err(StoreError::corrupt(
            "structural role columns on another read kind",
        ));
    }
    let index_key = row.get::<_, Option<Vec<u8>>>(6)?;
    let blob_oid = row.get::<_, Option<String>>(7)?;
    let subject = row.get::<_, Option<Vec<u8>>>(8)?;
    let start_byte = row.get::<_, Option<i64>>(9)?;
    let end_byte = row.get::<_, Option<i64>>(10)?;
    let digest = row.get::<_, Option<Vec<u8>>>(11)?;
    let site_ordinal = row.get::<_, Option<i64>>(12)?;
    let decl_kind = row.get::<_, Option<String>>(13)?;
    let decl_signature = row.get::<_, Option<String>>(14)?;
    let workspace_fact_family = row.get::<_, Option<String>>(15)?;
    let fact_member = row.get::<_, Option<String>>(16)?;
    let fact_names = row.get::<_, Option<String>>(17)?;
    let has_copy_projection = row.as_ref().column_names().get(18) == Some(&"copy_owning_unit");
    if has_copy_projection && row.as_ref().column_count() < 25 {
        return Err(StoreError::corrupt("partial Rust Copy question projection"));
    }
    let copy_owning_unit = has_copy_projection
        .then(|| row.get::<_, Option<Vec<u8>>>(18))
        .transpose()?
        .flatten();
    let copy_target_unit = has_copy_projection
        .then(|| row.get::<_, Option<Vec<u8>>>(19))
        .transpose()?
        .flatten();
    let copy_module_path = has_copy_projection
        .then(|| row.get::<_, Option<String>>(20))
        .transpose()?
        .flatten();
    let copy_target_identity_digest = has_copy_projection
        .then(|| row.get::<_, Option<Vec<u8>>>(21))
        .transpose()?
        .flatten();
    let copy_census_version = has_copy_projection
        .then(|| row.get::<_, Option<i64>>(22))
        .transpose()?
        .flatten();
    let copy_config_digest = has_copy_projection
        .then(|| row.get::<_, Option<Vec<u8>>>(23))
        .transpose()?
        .flatten();
    let copy_producer_digest = has_copy_projection
        .then(|| row.get::<_, Option<Vec<u8>>>(24))
        .transpose()?
        .flatten();
    let has_variant_projection = row.as_ref().column_names().get(25) == Some(&"parse_variant_kind");
    let parse_variant_kind = has_variant_projection
        .then(|| row.get::<_, Option<String>>(25))
        .transpose()?
        .flatten();
    let parse_variant_digest = has_variant_projection
        .then(|| row.get::<_, Option<Vec<u8>>>(26))
        .transpose()?
        .flatten();
    let is_publication =
        kind == "lookup" && family.as_deref() == Some("stored_semantic_ir_publication");
    if !is_publication && (parse_variant_kind.is_some() || parse_variant_digest.is_some()) {
        return Err(StoreError::corrupt(
            "publication variant columns on another read kind",
        ));
    }
    let copy_columns = (
        copy_owning_unit,
        copy_target_unit,
        copy_module_path,
        copy_target_identity_digest,
        copy_census_version,
        copy_config_digest,
        copy_producer_digest,
    );
    let is_copy = kind == "lookup" && family.as_deref() == Some("rust_copy_absence");
    if !is_copy
        && (copy_columns.0.is_some()
            || copy_columns.1.is_some()
            || copy_columns.2.is_some()
            || copy_columns.3.is_some()
            || copy_columns.4.is_some()
            || copy_columns.5.is_some()
            || copy_columns.6.is_some())
    {
        return Err(StoreError::corrupt(
            "Rust Copy question columns on another read kind",
        ));
    }
    let is_workspace_fact = kind == "lookup" && family.as_deref() == Some("workspace_fact");
    if !is_workspace_fact
        && (workspace_fact_family.is_some() || fact_member.is_some() || fact_names.is_some())
    {
        return Err(StoreError::corrupt(
            "workspace fact columns on a different read kind",
        ));
    }

    let missing = |column: &str| StoreError::new(format!("read key `{kind}` has no {column}"));
    let key = match kind.as_str() {
        "file" => ReadKey::File {
            language: decode_language(languages.as_deref().ok_or_else(|| missing("language"))?)?,
            rel_path: Box::from(rel_path.ok_or_else(|| missing("path"))?.as_str()),
            blob: decode_oid(&blob_oid.ok_or_else(|| missing("blob"))?)?,
            parse_variant: match digest.as_deref() {
                None => brokk_bifrost_core::gitblob::ParseVariant::Empty,
                Some(bytes) => brokk_bifrost_core::gitblob::ParseVariant::Digest(
                    bytes
                        .try_into()
                        .map_err(|_| StoreError::corrupt("invalid File parse variant length"))?,
                ),
            },
        },
        "path_absent" => ReadKey::PathAbsent {
            language: decode_language(languages.as_deref().ok_or_else(|| missing("language"))?)?,
            rel_path: Box::from(rel_path.ok_or_else(|| missing("path"))?.as_str()),
        },
        "index" => ReadKey::Index {
            family: index_family_of(family.as_deref().ok_or_else(|| missing("family"))?)?,
            key: Box::from(index_key.ok_or_else(|| missing("key"))?.as_slice()),
        },
        "lookup" => {
            let label = family.as_deref().ok_or_else(|| missing("kind"))?;
            let lookup_kind = if let Some(registered) = PersistedDerivationFamily::of(label) {
                LookupKind::Derivation(registered.id)
            } else {
                lookup_kind_of(label)?
            };
            let question = if lookup_kind == LookupKind::StoredSemanticIrPublication {
                if !matches!(rel_path.as_deref(), Some(path) if !path.is_empty())
                    || !matches!(languages.as_deref(), Some(language) if !language.is_empty() && !language.contains(','))
                {
                    return Err(StoreError::corrupt(
                        "invalid publication path or storage language",
                    ));
                }
                if name.is_some()
                    || index_key.is_some()
                    || blob_oid.is_some()
                    || start_byte.is_some()
                    || end_byte.is_some()
                    || site_ordinal.is_some()
                    || decl_kind.is_some()
                    || decl_signature.is_some()
                    || workspace_fact_family.is_some()
                    || fact_member.is_some()
                    || fact_names.is_some()
                    || copy_columns.0.is_some()
                    || copy_columns.1.is_some()
                    || copy_columns.2.is_some()
                    || copy_columns.3.is_some()
                    || copy_columns.4.is_some()
                    || copy_columns.5.is_some()
                    || copy_columns.6.is_some()
                {
                    return Err(StoreError::corrupt(
                        "publication question carries unrelated columns",
                    ));
                }
                let parse_variant = match (parse_variant_kind.as_deref(), parse_variant_digest) {
                    (Some("empty"), None) => StoredSemanticIrParseVariant::Empty,
                    (Some("digest"), Some(digest)) => StoredSemanticIrParseVariant::Digest(
                        digest
                            .try_into()
                            .map_err(|_| StoreError::corrupt("invalid publication parse digest"))?,
                    ),
                    _ => return Err(StoreError::corrupt("invalid publication parse variant")),
                };
                LookupQuestion::StoredSemanticIrPublication(StoredSemanticIrPublicationQuestion {
                    rel_path: rel_path.ok_or_else(|| missing("path"))?.into_boxed_str(),
                    storage_language: languages
                        .ok_or_else(|| missing("language"))?
                        .into_boxed_str(),
                    subject: subject
                        .ok_or_else(|| missing("subject"))?
                        .try_into()
                        .map_err(|_| StoreError::corrupt("invalid publication subject"))?,
                    parse_variant,
                })
            } else if lookup_kind == LookupKind::CertifiedDefinitionAnswer {
                return Err(StoreError::corrupt(
                    "certified definition keys have no persisted schema",
                ));
            } else if let LookupKind::Derivation(_) = lookup_kind {
                let registered = PersistedDerivationFamily::of(label)
                    .ok_or_else(|| StoreError::corrupt("unregistered derivation family"))?;
                if languages.is_some() != registered.language
                    || subject.is_some() != registered.subject
                    || rel_path.is_some() != registered.rel_path
                    || name.is_some() != registered.name
                    || index_key.is_some()
                    || blob_oid.is_some()
                    || start_byte.is_some()
                    || end_byte.is_some()
                    || site_ordinal.is_some()
                    || decl_kind.is_some()
                    || decl_signature.is_some()
                    || workspace_fact_family.is_some()
                    || fact_member.is_some()
                    || fact_names.is_some()
                    || copy_columns.0.is_some()
                    || copy_columns.1.is_some()
                    || copy_columns.2.is_some()
                    || copy_columns.3.is_some()
                    || copy_columns.4.is_some()
                    || copy_columns.5.is_some()
                    || copy_columns.6.is_some()
                    || parse_variant_kind.is_some()
                    || parse_variant_digest.is_some()
                {
                    return Err(StoreError::corrupt("invalid derivation question columns"));
                }
                LookupQuestion::Derivation(DerivationQuestion {
                    language: languages.as_deref().map(decode_language).transpose()?,
                    subject: subject
                        .as_deref()
                        .map(|bytes| {
                            decode_digest(bytes, "derivation subject")
                                .map(|digest| *digest.as_bytes())
                        })
                        .transpose()?,
                    rel_path: rel_path.map(Into::into),
                    name: name.map(Into::into),
                })
            } else if lookup_kind == LookupKind::ExternalSelection {
                if languages.is_some()
                    || rel_path.is_some()
                    || name.is_some()
                    || index_key.is_some()
                    || blob_oid.is_some()
                    || start_byte.is_some()
                    || end_byte.is_some()
                    || site_ordinal.is_some()
                    || decl_kind.is_some()
                    || decl_signature.is_some()
                    || workspace_fact_family.is_some()
                    || fact_member.is_some()
                    || fact_names.is_some()
                    || copy_columns.0.is_some()
                    || copy_columns.1.is_some()
                    || copy_columns.2.is_some()
                    || copy_columns.3.is_some()
                    || copy_columns.4.is_some()
                    || copy_columns.5.is_some()
                    || copy_columns.6.is_some()
                    || parse_variant_kind.is_some()
                    || parse_variant_digest.is_some()
                {
                    return Err(StoreError::corrupt(
                        "external selection question carries unrelated columns",
                    ));
                }
                LookupQuestion::ExternalSelection {
                    question_digest: *decode_digest(
                        &subject.ok_or_else(|| missing("subject"))?,
                        "external selection question",
                    )?
                    .as_bytes(),
                }
            } else if lookup_kind == LookupKind::RustCopyAbsence {
                if rel_path.is_some()
                    || name.is_some()
                    || index_key.is_some()
                    || blob_oid.is_some()
                    || subject.is_some()
                    || start_byte.is_some()
                    || end_byte.is_some()
                    || site_ordinal.is_some()
                    || decl_kind.is_some()
                    || decl_signature.is_some()
                    || workspace_fact_family.is_some()
                    || fact_member.is_some()
                    || fact_names.is_some()
                    || languages.is_some()
                {
                    return Err(StoreError::corrupt(
                        "Rust Copy question carries unrelated columns",
                    ));
                }
                let (
                    Some(owning),
                    Some(target),
                    Some(module_path),
                    Some(identity),
                    Some(version),
                    Some(config),
                    Some(producer),
                ) = copy_columns
                else {
                    return Err(StoreError::corrupt("incomplete Rust Copy question columns"));
                };
                LookupQuestion::RustCopyAbsence {
                    owning_unit: decode_digest(&owning, "Rust Copy owning unit")?,
                    target_unit: decode_digest(&target, "Rust Copy target unit")?,
                    module_path: module_path.into_boxed_str(),
                    target_identity_digest: decode_digest(&identity, "Rust Copy target identity")?,
                    census_version: u32::try_from(version)
                        .map_err(|_| StoreError::corrupt("invalid Rust Copy census version"))?,
                    config_digest: decode_digest(&config, "Rust Copy configuration")?,
                    producer_digest: decode_digest(&producer, "Rust Copy producer")?,
                }
            } else if lookup_kind == LookupKind::WorkspaceFact {
                if start_byte.is_some()
                    || end_byte.is_some()
                    || site_ordinal.is_some()
                    || index_key.is_some()
                    || blob_oid.is_some()
                    || decl_kind.is_some()
                    || decl_signature.is_some()
                {
                    return Err(StoreError::corrupt(
                        "workspace fact carries unrelated question columns",
                    ));
                }
                let invalid = || StoreError::corrupt("inconsistent workspace fact subject columns");
                let scalar = |bytes: &[u8]| {
                    decode_digest(bytes, "workspace fact subject")
                        .map_err(|error| StoreError::corrupt(error.to_string()))
                };
                let subject = match (rel_path, name, subject, fact_member, fact_names) {
                    (None, None, None, None, None) => FactSubject::Whole,
                    (None, None, Some(class), None, None) => FactSubject::Class {
                        class: scalar(&class)?,
                    },
                    (Some(rel_path), None, None, None, None) => FactSubject::File {
                        rel_path: rel_path.into(),
                    },
                    (None, Some(name), None, None, None) => {
                        FactSubject::Named { name: name.into() }
                    }
                    (None, Some(owner), None, Some(member), None) => FactSubject::NamedMember {
                        owner: owner.into(),
                        member: member.into(),
                    },
                    (None, None, Some(class), Some(member), None) => FactSubject::ClassMember {
                        class: scalar(&class)?,
                        member: member.into(),
                    },
                    (None, None, None, Some(member), Some(names)) => {
                        let names: Vec<Box<str>> =
                            serde_json::from_str(&names).map_err(|error| {
                                StoreError::corrupt(format!("workspace fact names: {error}"))
                            })?;
                        if names.is_empty() || !names.windows(2).all(|pair| pair[0] < pair[1]) {
                            return Err(StoreError::corrupt(
                                "workspace fact names must be nonempty, sorted and deduplicated",
                            ));
                        }
                        FactSubject::name_group_member(names, member.into())
                    }
                    (Some(rel_path), Some(owner), environment, Some(member), None) => {
                        FactSubject::FileNamedMember {
                            rel_path: rel_path.into(),
                            owner: owner.into(),
                            member: member.into(),
                            environment: environment.as_deref().map(scalar).transpose()?,
                        }
                    }
                    _ => return Err(invalid()),
                };
                LookupQuestion::WorkspaceFact {
                    family: workspace_fact_family_of(
                        workspace_fact_family
                            .as_deref()
                            .ok_or_else(|| StoreError::corrupt("missing workspace fact family"))?,
                    )?,
                    language: decode_language(
                        languages.as_deref().ok_or_else(|| {
                            StoreError::corrupt("missing workspace fact language")
                        })?,
                    )
                    .map_err(|error| StoreError::corrupt(error.to_string()))?,
                    subject,
                }
            } else {
                if matches!(
                    lookup_kind,
                    LookupKind::StructuralNameInventory
                        | LookupKind::StructuralRoleNameInventory
                        | LookupKind::StructuralRecoveredInventory
                ) {
                    let language =
                        decode_language(languages.as_deref().ok_or_else(|| missing("languages"))?)?;
                    let authority = decode_digest(
                        &subject.ok_or_else(|| missing("subject"))?,
                        "structural authority",
                    )?;
                    if rel_path.is_some()
                        || start_byte.is_some()
                        || end_byte.is_some()
                        || site_ordinal.is_some()
                        || index_key.is_some()
                        || blob_oid.is_some()
                        || decl_kind.is_some()
                        || decl_signature.is_some()
                        || workspace_fact_family.is_some()
                        || fact_member.is_some()
                        || fact_names.is_some()
                    {
                        return Err(StoreError::corrupt(
                            "structural inventory carries unrelated columns",
                        ));
                    }
                    match lookup_kind {
                        LookupKind::StructuralNameInventory => LookupQuestion::StructuralName {
                            language,
                            name: name.ok_or_else(|| missing("name"))?.into(),
                            authority,
                        },
                        LookupKind::StructuralRoleNameInventory => {
                            LookupQuestion::StructuralRoleName {
                                language,
                                role: Role::from_label(
                                    structural_role
                                        .as_deref()
                                        .ok_or_else(|| missing("structural_role"))?,
                                )
                                .ok_or_else(|| StoreError::corrupt("unknown structural role"))?,
                                name: name.ok_or_else(|| missing("name"))?.into(),
                                keyword: match structural_keyword
                                    .ok_or_else(|| missing("structural_keyword"))?
                                {
                                    0 => false,
                                    1 => true,
                                    _ => {
                                        return Err(StoreError::corrupt(
                                            "invalid structural keyword",
                                        ));
                                    }
                                },
                                authority,
                            }
                        }
                        LookupKind::StructuralRecoveredInventory => {
                            if name.is_some() {
                                return Err(StoreError::corrupt(
                                    "recovered inventory carries name",
                                ));
                            }
                            LookupQuestion::StructuralRecovered {
                                language,
                                authority,
                            }
                        }
                        _ => unreachable!(),
                    }
                } else if matches!(
                    lookup_kind,
                    LookupKind::RustBoundTraitImplInventory
                        | LookupKind::RustTraitsImplementedByInventory
                ) {
                    if languages.as_deref() != Some("rust")
                        || index_key.is_some()
                        || site_ordinal.is_some()
                        || name.is_some()
                        || subject.is_some()
                        || start_byte != end_byte
                        || decl_kind.is_some()
                        || decl_signature.is_some()
                    {
                        return Err(StoreError::corrupt("invalid Rust placed declaration"));
                    }
                    let oid =
                        Oid::from_str(blob_oid.as_deref().ok_or_else(|| missing("blob_oid"))?)?;
                    LookupQuestion::RustPlacedDeclaration {
                        blob: oid.as_bytes().try_into().expect("git OIDs are 20 bytes"),
                        declaration: u32::try_from(
                            start_byte.ok_or_else(|| missing("declaration"))?,
                        )
                        .map_err(|_| StoreError::corrupt("invalid declaration ID"))?,
                        rel_path: rel_path.ok_or_else(|| missing("rel_path"))?.into(),
                    }
                } else {
                    match (rel_path, name, subject, start_byte, end_byte) {
                        (None, Some(name), None, None, None) => LookupQuestion::Name {
                            language: languages.as_deref().map(decode_language).transpose()?,
                            name: Box::from(name.as_str()),
                        },
                        (Some(rel_path), Some(fq_name), None, None, None) => {
                            LookupQuestion::Declaration {
                                rel_path: Box::from(rel_path.as_str()),
                                fq_name: Box::from(fq_name.as_str()),
                                kind: CodeUnitType::ALL
                                    .into_iter()
                                    .find(|kind| {
                                        Some(kind.identity_label()) == decl_kind.as_deref()
                                    })
                                    .ok_or_else(|| {
                                        StoreError::new(format!(
                                            "unknown declaration kind {decl_kind:?}"
                                        ))
                                    })?,
                                signature: decl_signature,
                            }
                        }
                        (Some(rel_path), None, None, None, None) => LookupQuestion::File {
                            rel_path: Box::from(rel_path.as_str()),
                        },
                        (Some(rel_path), None, Some(subject), Some(rank), Some(end))
                            if rank == end
                                && rank >= 0
                                && matches!(
                                    lookup_kind,
                                    LookupKind::Dispatch | LookupKind::ProcedureDispatch
                                ) =>
                        {
                            if site_ordinal.is_some_and(|ordinal| ordinal != rank) {
                                return Err(StoreError::corrupt("call rank columns disagree"));
                            }
                            LookupQuestion::CallSite {
                                rel_path: Box::from(rel_path.as_str()),
                                procedure: decode_digest(&subject, "procedure lineage")?,
                                site: CallSiteLocator {
                                    ordinal: rank as usize,
                                },
                            }
                        }
                        (None, None, Some(identity), None, None) => LookupQuestion::Summary {
                            identity: decode_digest(&identity, "summary identity")?,
                        },
                        columns => {
                            return Err(StoreError::new(format!(
                                "read key `lookup` has no question in its columns: {columns:?}"
                            )));
                        }
                    }
                }
            };
            if !lookup_question_matches_kind(lookup_kind, &question) {
                return Err(StoreError::new(format!(
                    "lookup kind `{}` cannot carry question `{}`",
                    lookup_kind.stable_label(),
                    question.stable_label()
                )));
            }
            ReadKey::Lookup {
                kind: lookup_kind,
                question,
                digest: {
                    let answer = digest.as_deref().ok_or_else(|| {
                        if is_workspace_fact {
                            StoreError::corrupt("missing workspace fact answer")
                        } else {
                            missing("answer")
                        }
                    })?;
                    decode_digest(answer, "lookup answer").map_err(|error| {
                        if is_workspace_fact {
                            StoreError::corrupt(error.to_string())
                        } else {
                            error
                        }
                    })?
                },
            }
        }
        "artifact" => ReadKey::Artifact {
            id: DerivedArtifactId::new(
                artifact_kind_of(family.as_deref().ok_or_else(|| missing("kind"))?)?,
                decode_digest(
                    &subject.ok_or_else(|| missing("fingerprint"))?,
                    "artifact fingerprint",
                )?,
            ),
            rel_path: rel_path.map(|path| Box::from(path.as_str())),
        },
        "scope" => {
            let languages = languages.ok_or_else(|| missing("languages"))?;
            let mut scope = Vec::new();
            for label in languages.split(',') {
                scope.push(decode_language(label)?);
            }
            ReadKey::Scope {
                languages: scope.into_boxed_slice(),
                identity: WorkspaceContentIdentity::from_digest(decode_digest(
                    &digest.ok_or_else(|| missing("identity"))?,
                    "scope identity",
                )?),
            }
        }
        "models" => ReadKey::Models(decode_digest(
            &digest.ok_or_else(|| missing("digest"))?,
            "model set",
        )?),
        "policy" => ReadKey::Policy {
            semantic_hash: decode_digest(
                &subject.ok_or_else(|| missing("semantic hash"))?,
                "policy semantic hash",
            )?,
            source: decode_digest(
                &digest.ok_or_else(|| missing("source digest"))?,
                "policy source",
            )?,
        },
        "configuration" => ReadKey::Configuration(decode_digest(
            &digest.ok_or_else(|| missing("digest"))?,
            "configuration",
        )?),
        "epoch" => ReadKey::Epoch(decode_digest(
            &digest.ok_or_else(|| missing("digest"))?,
            "epoch",
        )?),
        other => {
            return Err(StoreError::new(format!("unknown read key kind `{other}`")));
        }
    };
    let rebuilt = key.canonical_digest();
    if rebuilt.as_bytes().as_slice() != key_digest.as_slice() {
        return Err(StoreError::corrupt(format!(
            "read key `{kind}` did not rebuild to its stored identity {}",
            hex_of(&key_digest)
        )));
    }
    Ok(key)
}

fn lookup_question_matches_kind(kind: LookupKind, question: &LookupQuestion) -> bool {
    if matches!(
        kind,
        LookupKind::RustBoundTraitImplInventory | LookupKind::RustTraitsImplementedByInventory
    ) || matches!(question, LookupQuestion::RustPlacedDeclaration { .. })
    {
        return matches!(
            kind,
            LookupKind::RustBoundTraitImplInventory | LookupKind::RustTraitsImplementedByInventory
        ) && matches!(question, LookupQuestion::RustPlacedDeclaration { .. });
    }
    if kind == LookupKind::CertifiedDefinitionAnswer
        || matches!(question, LookupQuestion::CertifiedDefinition { .. })
    {
        return matches!(
            (kind, question),
            (
                LookupKind::CertifiedDefinitionAnswer,
                LookupQuestion::CertifiedDefinition { .. }
            )
        );
    }
    if kind == LookupKind::StoredSemanticIrPublication
        || matches!(question, LookupQuestion::StoredSemanticIrPublication(..))
    {
        return matches!(
            (kind, question),
            (
                LookupKind::StoredSemanticIrPublication,
                LookupQuestion::StoredSemanticIrPublication(..)
            )
        );
    }
    if let LookupKind::Derivation(id) = kind {
        return matches!(question, LookupQuestion::Derivation(q) if PersistedDerivationFamily::of(id.0).is_some_and(|family| family.admits(q)));
    }
    if matches!(question, LookupQuestion::Derivation(_)) {
        return false;
    }
    if matches!(
        kind,
        LookupKind::RustUnresolvedTraitImplInventory
            | LookupKind::RustModuleImportCandidateInventory
            | LookupKind::RustIdentifierOccurrenceInventory
            | LookupKind::RustAliasBlobInventory
            | LookupKind::RustMacroExpansionInventory
    ) {
        return matches!(
            question,
            LookupQuestion::Name {
                language: Some(Language::Rust),
                ..
            }
        );
    }
    if kind == LookupKind::RustCopyAbsence
        || matches!(question, LookupQuestion::RustCopyAbsence { .. })
    {
        return matches!(
            (kind, question),
            (
                LookupKind::RustCopyAbsence,
                LookupQuestion::RustCopyAbsence { .. }
            )
        );
    }
    if kind == LookupKind::ExternalSelection
        || matches!(question, LookupQuestion::ExternalSelection { .. })
    {
        return matches!(
            (kind, question),
            (
                LookupKind::ExternalSelection,
                LookupQuestion::ExternalSelection { .. }
            )
        );
    }
    if matches!(
        kind,
        LookupKind::StructuralNameInventory
            | LookupKind::StructuralRoleNameInventory
            | LookupKind::StructuralRecoveredInventory
    ) || matches!(
        question,
        LookupQuestion::StructuralName { .. }
            | LookupQuestion::StructuralRecovered { .. }
            | LookupQuestion::StructuralRoleName { .. }
    ) {
        return matches!(
            (kind, question),
            (
                LookupKind::StructuralNameInventory,
                LookupQuestion::StructuralName { .. }
            ) | (
                LookupKind::StructuralRoleNameInventory,
                LookupQuestion::StructuralRoleName { .. }
            ) | (
                LookupKind::StructuralRecoveredInventory,
                LookupQuestion::StructuralRecovered { .. }
            )
        );
    }
    if kind == LookupKind::WorkspaceFact || matches!(question, LookupQuestion::WorkspaceFact { .. })
    {
        return matches!(
            (kind, question),
            (
                LookupKind::WorkspaceFact,
                LookupQuestion::WorkspaceFact { .. }
            )
        );
    }
    matches!(
        (kind, question),
        (
            LookupKind::ResolvedName
                | LookupKind::Definitions
                | LookupKind::IdentifierCandidates
                | LookupKind::ShortNameCandidates,
            LookupQuestion::Name { .. },
        ) | (
            LookupKind::DeclarationCandidates,
            LookupQuestion::Declaration { .. }
        ) | (LookupKind::Dispatch, LookupQuestion::CallSite { .. })
            | (
                LookupKind::ProcedureDispatch,
                LookupQuestion::CallSite { .. }
            )
    ) || (!matches!(
        kind,
        LookupKind::ResolvedName
            | LookupKind::Definitions
            | LookupKind::IdentifierCandidates
            | LookupKind::ShortNameCandidates
            | LookupKind::Dispatch
            | LookupKind::ProcedureDispatch
            | LookupKind::DeclarationCandidates
    ) && !matches!(
        question,
        LookupQuestion::Name { .. } | LookupQuestion::CallSite { .. }
    ))
}

/// The sorted language labels of one scope, as the one text column a scope
/// key is found and rebuilt by.
fn language_list(languages: &[Language]) -> String {
    languages
        .iter()
        .map(|language| language.config_label())
        .collect::<Vec<_>>()
        .join(",")
}

fn hex_of(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn decode_digest(bytes: &[u8], what: &str) -> Result<StableDigest> {
    let array = <[u8; 32]>::try_from(bytes)
        .map_err(|_| StoreError::new(format!("{what} digest has {} bytes, not 32", bytes.len())))?;
    Ok(StableDigest::from_array(array))
}

fn decode_oid(text: &str) -> Result<Oid> {
    text.parse()
        .map_err(|error| StoreError::new(format!("unreadable blob `{text}`: {error}")))
}

fn decode_language(label: &str) -> Result<Language> {
    if label == Language::None.config_label() {
        return Ok(Language::None);
    }
    super::canonical_language_label(label)
        .ok_or_else(|| StoreError::new(format!("unknown language label `{label}`")))
}

/// Every index family, so a label decodes to the variant that spells it.
const ALL_INDEX_FAMILIES: [IndexFamily; 9] = [
    IndexFamily::DefinitionExact,
    IndexFamily::DefinitionNormalizedTail,
    IndexFamily::DefinitionIdentifier,
    IndexFamily::ReferenceIdentifier,
    IndexFamily::ImportPathSegment,
    IndexFamily::PackageMembership,
    IndexFamily::Supertype,
    IndexFamily::SupertypeLookupPath,
    IndexFamily::PathSymbol,
];

/// Every derived-value lookup kind.
const ALL_LOOKUP_KINDS: [LookupKind; 31] = [
    LookupKind::CertifiedDefinitionAnswer,
    LookupKind::StoredSemanticIrPublication,
    LookupKind::ResolvedName,
    LookupKind::Definitions,
    LookupKind::IdentifierCandidates,
    LookupKind::ShortNameCandidates,
    LookupKind::RustTraitsImplementedByInventory,
    LookupKind::RustBoundTraitImplInventory,
    LookupKind::RustUnresolvedTraitImplInventory,
    LookupKind::RustModuleImportCandidateInventory,
    LookupKind::RustIdentifierOccurrenceInventory,
    LookupKind::RustAliasBlobInventory,
    LookupKind::RustMacroExpansionInventory,
    LookupKind::DeclarationFacts,
    LookupKind::DeclarationCandidates,
    LookupKind::SignatureMetadata,
    LookupKind::Callers,
    LookupKind::Callees,
    LookupKind::Usages,
    LookupKind::Importers,
    LookupKind::ReferenceCandidates,
    LookupKind::Descendants,
    LookupKind::Dispatch,
    LookupKind::ProcedureDispatch,
    LookupKind::ProcedureSummary,
    LookupKind::WorkspaceFact,
    LookupKind::StructuralNameInventory,
    LookupKind::StructuralRoleNameInventory,
    LookupKind::StructuralRecoveredInventory,
    LookupKind::RustCopyAbsence,
    LookupKind::ExternalSelection,
];

/// Every derived-artifact kind.
const ALL_ARTIFACT_KINDS: [DerivedArtifactKind; 8] = [
    DerivedArtifactKind::SemanticArtifact,
    DerivedArtifactKind::ProcedureSummary,
    DerivedArtifactKind::FlowSnapshot,
    DerivedArtifactKind::PolicyReport,
    DerivedArtifactKind::DerivedQueryLayer,
    DerivedArtifactKind::WorkspaceUsageGraph,
    DerivedArtifactKind::StructuralIndex,
    DerivedArtifactKind::PolicyEvaluationUnit,
];

fn index_family_of(label: &str) -> Result<IndexFamily> {
    ALL_INDEX_FAMILIES
        .into_iter()
        .find(|family| family.stable_label() == label)
        .ok_or_else(|| StoreError::new(format!("unknown index family `{label}`")))
}

fn workspace_fact_family_of(label: &str) -> Result<WorkspaceFactFamily> {
    WorkspaceFactFamily::from_label(label)
        .ok_or_else(|| StoreError::corrupt(format!("unknown workspace fact family `{label}`")))
}

fn lookup_kind_of(label: &str) -> Result<LookupKind> {
    ALL_LOOKUP_KINDS
        .into_iter()
        .find(|kind| kind.stable_label() == label)
        .ok_or_else(|| StoreError::new(format!("unknown lookup kind `{label}`")))
}

fn artifact_kind_of(label: &str) -> Result<DerivedArtifactKind> {
    ALL_ARTIFACT_KINDS
        .into_iter()
        .find(|kind| kind.stable_label() == label)
        .ok_or_else(|| StoreError::new(format!("unknown derived artifact kind `{label}`")))
}

#[cfg(test)]
pub(super) fn workspace_fact_subjects() -> Vec<FactSubject> {
    let class = StableDigest::sha256(b"class");
    vec![
        FactSubject::Whole,
        FactSubject::Class { class },
        FactSubject::File {
            rel_path: "src/item.py".into(),
        },
        FactSubject::Named {
            name: "pkg.Item".into(),
        },
        FactSubject::NamedMember {
            owner: "pkg.Item".into(),
            member: "method".into(),
        },
        FactSubject::ClassMember {
            class,
            member: "method".into(),
        },
        FactSubject::name_group_member(vec!["pkg.A".into(), "pkg.B".into()], "method".into()),
        FactSubject::FileNamedMember {
            rel_path: "src/item.py".into(),
            owner: "pkg.Item".into(),
            member: "method".into(),
            environment: None,
        },
        FactSubject::FileNamedMember {
            rel_path: "src/item.py".into(),
            owner: "pkg.Item".into(),
            member: "method".into(),
            environment: Some(StableDigest::sha256(b"environment")),
        },
    ]
}

#[cfg(test)]
mod tests {
    use rusqlite::{Connection, params};

    use super::*;
    use brokk_bifrost_semantic::analyzer::semantic::read_ledger::CertifiedDefinitionKind;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10187: a new certificate arm could silently change existing persisted read-key columns"
    )]
    fn existing_read_key_columns_golden() {
        let digest = StableDigest::sha256(b"golden answer");
        let mut keys = vec![
            ReadKey::file(
                Language::Go,
                "src/main.go",
                Oid::zero(),
                brokk_bifrost_core::gitblob::ParseVariant::Empty,
            ),
            ReadKey::path_absent(Language::Go, "src/missing.go"),
            ReadKey::index(IndexFamily::DefinitionExact, b"main"),
            ReadKey::artifact(
                DerivedArtifactId::semantic_artifact(digest),
                Some("src/main.go"),
            ),
            ReadKey::scope(
                [Language::Go],
                WorkspaceContentIdentity::from_digest(digest),
            ),
            ReadKey::Models(digest),
            ReadKey::Policy {
                semantic_hash: digest,
                source: digest,
            },
            ReadKey::Configuration(digest),
            ReadKey::Epoch(digest),
        ];
        for kind in ALL_LOOKUP_KINDS.into_iter().filter(|kind| {
            !matches!(
                kind,
                LookupKind::RustBoundTraitImplInventory
                    | LookupKind::RustTraitsImplementedByInventory
                    | LookupKind::CertifiedDefinitionAnswer
                    | LookupKind::RustUnresolvedTraitImplInventory
                    | LookupKind::RustModuleImportCandidateInventory
                    | LookupKind::RustIdentifierOccurrenceInventory
                    | LookupKind::RustAliasBlobInventory
                    | LookupKind::RustMacroExpansionInventory
            )
        }) {
            let question = match kind {
                LookupKind::StoredSemanticIrPublication => {
                    LookupQuestion::StoredSemanticIrPublication(
                        StoredSemanticIrPublicationQuestion {
                            rel_path: "src/main.go".into(),
                            storage_language: "go".into(),
                            subject: [3; 32],
                            parse_variant: StoredSemanticIrParseVariant::Empty,
                        },
                    )
                }
                LookupKind::Derivation(_) => {
                    unreachable!("derivations have their own registered families")
                }
                LookupKind::RustCopyAbsence => LookupQuestion::RustCopyAbsence {
                    owning_unit: digest,
                    target_unit: digest,
                    module_path: "crate".into(),
                    target_identity_digest: digest,
                    census_version: 1,
                    config_digest: digest,
                    producer_digest: digest,
                },
                LookupKind::StructuralNameInventory => LookupQuestion::StructuralName {
                    language: Language::Go,
                    name: "main".into(),
                    authority: digest,
                },
                LookupKind::StructuralRecoveredInventory => LookupQuestion::StructuralRecovered {
                    language: Language::Go,
                    authority: digest,
                },
                LookupKind::StructuralRoleNameInventory => LookupQuestion::StructuralRoleName {
                    language: Language::Go,
                    role: Role::Callee,
                    name: "main".into(),
                    keyword: false,
                    authority: digest,
                },
                LookupKind::ExternalSelection => LookupQuestion::ExternalSelection {
                    question_digest: [5; 32],
                },
                LookupKind::WorkspaceFact => LookupQuestion::WorkspaceFact {
                    family: WorkspaceFactFamily::from_label("jvm_selected_root_presence").unwrap(),
                    language: Language::Java,
                    subject: FactSubject::Named {
                        name: "java.lang.Object".into(),
                    },
                },
                LookupKind::ResolvedName
                | LookupKind::Definitions
                | LookupKind::IdentifierCandidates
                | LookupKind::ShortNameCandidates => LookupQuestion::Name {
                    language: Some(Language::Go),
                    name: "main".into(),
                },
                LookupKind::DeclarationCandidates => LookupQuestion::Declaration {
                    rel_path: "src/main.go".into(),
                    fq_name: "main".into(),
                    kind: CodeUnitType::Function,
                    signature: None,
                },
                LookupKind::Dispatch | LookupKind::ProcedureDispatch => LookupQuestion::CallSite {
                    rel_path: "src/main.go".into(),
                    procedure: digest,
                    site: CallSiteLocator { ordinal: 0 },
                },
                _ => LookupQuestion::File {
                    rel_path: "src/main.go".into(),
                },
            };
            keys.push(ReadKey::lookup(kind, question, digest));
        }
        let family = PersistedDerivationFamily::of("derivation:unit_summary:v1").unwrap();
        keys.push(ReadKey::lookup(
            LookupKind::Derivation(family.id),
            LookupQuestion::Derivation(DerivationQuestion {
                language: Some(Language::Rust),
                subject: Some([7; 32]),
                rel_path: None,
                name: None,
            }),
            digest,
        ));
        let case = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/read-key-columns/expected.txt");
        let actual = {
            let mut rendered = String::new();
            for key in &keys {
                let columns = ReadKeyColumns::of(key).unwrap();
                rendered.push_str(&format!("{:?}: kind={} family={:?} languages={:?} path={:?} name={:?} index={:?} blob={:?} subject={:?} start={:?} end={:?} digest={:?} ordinal={:?} decl_kind={:?} signature={:?} fact_family={:?} fact_member={:?} fact_names={:?} copy_owner={:?} copy_target={:?} copy_path={:?} copy_identity={:?} copy_census={:?} copy_config={:?} copy_producer={:?} parse_kind={:?} parse_digest={:?} key_digest={:?}\n",
                    key.stable_label(), columns.kind, columns.family, columns.languages, columns.rel_path, columns.name,
                    columns.index_key, columns.blob_oid, columns.subject, columns.start_byte, columns.end_byte,
                    columns.digest, columns.site_ordinal, columns.decl_kind, columns.decl_signature,
                    columns.workspace_fact_family, columns.fact_member, columns.fact_names, columns.copy_owning_unit,
                    columns.copy_target_unit, columns.copy_module_path, columns.copy_target_identity_digest,
                    columns.copy_census_version, columns.copy_config_digest, columns.copy_producer_digest,
                    columns.parse_variant_kind, columns.parse_variant_digest, columns.key_digest));
            }
            rendered
        };
        if std::env::var_os("BIFROST_BLESS").is_some() {
            std::fs::write(&case, &actual).expect("write read-key golden");
        }
        assert_eq!(
            std::fs::read_to_string(&case).expect("read read-key golden"),
            actual,
            "read-key columns changed; use BIFROST_BLESS=1 to update"
        );
    }

    #[test]
    #[should_panic(
        expected = "a certified definition key is not persisted until #10325 adds its schema with a migration"
    )]
    #[brokk_bifrost_test_macros::hardwon(
        "#10187: certified definition columns violated both persisted read schemas"
    )]
    fn certified_definition_keys_cannot_be_encoded() {
        let key = ReadKey::lookup(
            LookupKind::CertifiedDefinitionAnswer,
            LookupQuestion::certified_definition(
                CertifiedDefinitionKind::Exact,
                "pkg.target",
                [Language::Rust],
            ),
            StableDigest::sha256(b"answer"),
        );
        ReadKeyColumns::of(&key).unwrap();
    }

    /// A memory-only Derivation lookup is refused with an error, not a
    /// panic, so a publication path that misses the ledger gate fails in
    /// the store instead of crashing it or writing an unreplayable key.
    #[test]
    fn a_memory_only_key_is_refused_with_an_error() {
        let family =
            PersistedDerivationFamily::of("derivation:rust_call_site_resolution:v1").unwrap();
        assert!(family.memory_only);
        let key = ReadKey::lookup(
            LookupKind::Derivation(family.id),
            LookupQuestion::Derivation(DerivationQuestion {
                language: Some(Language::Rust),
                subject: Some([7; 32]),
                rel_path: Some("src/lib.rs".into()),
                name: Some("0..3".into()),
            }),
            StableDigest::sha256(b"site answer"),
        );
        assert!(!key.is_persistable());
        let error = ReadKeyColumns::of(&key).err().expect("refused");
        assert!(error.to_string().contains("memory-only"), "{error}");
    }

    #[test]
    fn stored_publication_codec_round_trips_raw_language_and_variants() {
        for variant in [
            StoredSemanticIrParseVariant::Empty,
            StoredSemanticIrParseVariant::Digest([7; 32]),
        ] {
            for answer in [
                brokk_bifrost_semantic::analyzer::semantic::read_ledger::StoredSemanticIrPublicationAnswer::NoHead,
                brokk_bifrost_semantic::analyzer::semantic::read_ledger::StoredSemanticIrPublicationAnswer::StaleEpoch,
                brokk_bifrost_semantic::analyzer::semantic::read_ledger::StoredSemanticIrPublicationAnswer::ContentMismatch,
                brokk_bifrost_semantic::analyzer::semantic::read_ledger::StoredSemanticIrPublicationAnswer::Present { active_epoch: "epoch-x".into(), row_digest: [9; 32] },
            ] {
                let key = ReadKey::lookup(
                    LookupKind::StoredSemanticIrPublication,
                    LookupQuestion::StoredSemanticIrPublication(StoredSemanticIrPublicationQuestion {
                        rel_path: "src/File.kt".into(),
                        storage_language: "raw-kotlin-key".into(),
                        subject: [3; 32],
                        parse_variant: variant,
                    }),
                    answer.canonical_digest(),
                );
                let columns = ReadKeyColumns::of(&key).unwrap();
                assert_eq!(columns.languages.as_deref(), Some("raw-kotlin-key"));
                assert_eq!(decode_columns(&columns).unwrap(), key);
            }
        }
    }

    #[test]
    fn retired_derivation_read_sets_decode_and_replay_as_misses() {
        use brokk_bifrost_core::retention_budget::{RetainedBytes, RetentionBudget};
        use brokk_bifrost_semantic::analyzer::semantic::derivation::*;
        use std::sync::Arc;

        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        struct Binding;
        impl RetainedBytes for Binding {
            fn retained_bytes(&self) -> usize {
                std::mem::size_of::<Self>()
            }
        }
        impl DerivationRevision for Binding {
            fn is_established(&self) -> bool {
                true
            }
        }
        impl DerivationAuthority for Binding {
            fn retention_refusal(&self) -> Option<NotReusableCause> {
                None
            }
        }
        struct NoInputs;
        impl BaseInputs<Binding, Binding> for NoInputs {
            fn unchanged(&self, _: &ReadKey, _: &Binding, _: &Binding, _: &Binding) -> bool {
                panic!("retired kinds cannot verify inputs")
            }
        }
        struct NoCapture;
        impl CaptureHook<Binding, Binding> for NoCapture {
            fn capture(&self, _: &Binding, _: &Binding, _: &mut dyn FnMut()) -> CaptureReceipt {
                panic!("retired kinds cannot compute")
            }
            fn report_unattributed(&self) {
                panic!("unexpected capture")
            }
            fn report_execution_dependence(&self, _: NotReusableCause) {
                panic!("unexpected capture")
            }
            fn report_reuse_refusal(&self, _: NotReusableCause) {
                panic!("unexpected capture")
            }
            fn report_persistence_refusals(&self, _: usize) {
                panic!("unexpected capture")
            }
            fn replay_reasons(&self, _: &[String]) {
                panic!("unexpected capture")
            }
            fn record(&self, _: ReadKey) {
                panic!("unexpected capture")
            }
        }
        let budget = RetentionBudget::new(1_000_000);
        let engine = DerivationEngine::new(&budget, Arc::new(NoCapture), Arc::new(NoInputs));
        let conn = Connection::open_in_memory().unwrap();
        for (label, subject, path, name) in [
            ("derivation:rust_selection_content:v1", None, None, None),
            ("derivation:rust_selection_content:v2", None, None, None),
            (
                "derivation:rust_forward_scope_witness:v1",
                Some(vec![7u8; 32]),
                Some("src/lib.rs"),
                None,
            ),
            (
                "derivation:rust_call_site_resolution:v1",
                Some(vec![7u8; 32]),
                Some("src/lib.rs"),
                Some("0:3"),
            ),
        ] {
            let family = PersistedDerivationFamily::of(label).unwrap();
            let key = ReadKey::lookup(
                LookupKind::Derivation(family.id),
                LookupQuestion::Derivation(DerivationQuestion {
                    language: Some(Language::Rust),
                    subject: subject.as_ref().map(|v| v.as_slice().try_into().unwrap()),
                    rel_path: path.map(Into::into),
                    name: name.map(Into::into),
                }),
                StableDigest::sha256(b"retired answer"),
            );
            // Construct historical stored columns directly: the call-site arm
            // is memory-only and the current encoder correctly refuses it.
            let decoded = conn.query_row(
                "SELECT ?1, 'lookup', ?2, 'rust', ?3, ?4, NULL, NULL, ?5, NULL, NULL, ?6, NULL, NULL, NULL, NULL, NULL, NULL",
                params![key.canonical_digest().as_bytes().as_slice(), label, path, name, subject, StableDigest::sha256(b"retired answer").as_bytes().as_slice()],
                |row| Ok(decode_read_key(row).unwrap()),
            ).unwrap();
            assert_eq!(decoded, key, "{label}");
            let ReadKey::Lookup {
                kind: LookupKind::Derivation(id),
                question: LookupQuestion::Derivation(question),
                ..
            } = decoded
            else {
                panic!("expected derivation")
            };
            assert!(
                matches!(
                    engine.replay(id, &question, Binding, Binding),
                    ReplayedDemand::Unavailable(_)
                ),
                "{label}"
            );
        }
    }

    #[test]
    fn derivation_families_round_trip_and_reject_malformed_rows() {
        let schema = include_str!("../../../../bifrost-core/migrations/cache/current-schema.sql");
        let start = schema.find("CREATE TABLE \"policy_read_keys\"(").unwrap();
        let end = start + schema[start..].find(") STRICT;").unwrap() + ") STRICT;".len();
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(&schema[start..end]).unwrap();
        let subject = [7; 32];
        let answer = StableDigest::sha256(b"derivation answer");
        for (label, language, subject) in [
            (
                "derivation:unit_summary:v1",
                Some(Language::Rust),
                Some(subject),
            ),
            ("derivation:rust_unit_set:v1", Some(Language::Rust), None),
            (
                "derivation:rust_unit_dependency_identities:v1",
                Some(Language::Rust),
                Some(subject),
            ),
            (
                "derivation:rust_unit_routes:v1",
                Some(Language::Rust),
                Some(subject),
            ),
            ("derivation:rust_route_directory:v1", None, None),
            ("derivation:rust_route_index:v1", None, None),
            // Retired by v2; a stored row must still decode, so its unit
            // recomputes instead of failing to load.
            (
                "derivation:rust_selection_content:v1",
                Some(Language::Rust),
                None,
            ),
        ] {
            let family = PersistedDerivationFamily::of(label).unwrap();
            let key = ReadKey::lookup(
                LookupKind::Derivation(family.id),
                LookupQuestion::Derivation(DerivationQuestion {
                    language,
                    subject,
                    rel_path: None,
                    name: None,
                }),
                answer,
            );
            let columns = ReadKeyColumns::of(&key).unwrap();
            connection.execute(
                "INSERT INTO policy_read_keys(key_digest, kind, family, languages, subject, digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![columns.key_digest.as_slice(), columns.kind, columns.family, columns.languages, columns.subject, columns.digest],
            ).unwrap();
            let read = || {
                connection.query_row(
                "SELECT key_digest, kind, family, languages, rel_path, name, index_key, blob_oid, subject, start_byte, end_byte, digest, site_ordinal, decl_kind, decl_signature, workspace_fact_family, fact_member, fact_names, copy_owning_unit, copy_target_unit, copy_module_path, copy_target_identity_digest, copy_census_version, copy_config_digest, copy_producer_digest, parse_variant_kind, parse_variant_digest, structural_role, structural_keyword FROM policy_read_keys WHERE key_digest = ?1",
                [columns.key_digest.as_slice()],
                |row| Ok(decode_read_key(row).map_err(|error| error.to_string())),
            ).unwrap()
            };
            assert_eq!(read(), Ok(key.clone()), "{label}");
            for sql in [
                "UPDATE policy_read_keys SET family = 'derivation:unknown:v1' WHERE key_digest = ?1",
                "UPDATE policy_read_keys SET family = 'derivation:unit_summary:v2' WHERE key_digest = ?1",
                "UPDATE policy_read_keys SET name = 'extra' WHERE key_digest = ?1",
                "UPDATE policy_read_keys SET languages = NULL WHERE key_digest = ?1",
                "UPDATE policy_read_keys SET subject = NULL WHERE key_digest = ?1",
                "UPDATE policy_read_keys SET key_digest = zeroblob(32) WHERE key_digest = ?1",
            ] {
                if sql.contains("languages = NULL") && language.is_none()
                    || sql.contains("subject = NULL") && subject.is_none()
                {
                    continue;
                }
                connection.execute_batch("SAVEPOINT malformed").unwrap();
                connection
                    .execute(sql, [columns.key_digest.as_slice()])
                    .unwrap();
                let result = connection.query_row(
                    "SELECT key_digest, kind, family, languages, rel_path, name, index_key, blob_oid, subject, start_byte, end_byte, digest, site_ordinal, decl_kind, decl_signature, workspace_fact_family, fact_member, fact_names, copy_owning_unit, copy_target_unit, copy_module_path, copy_target_identity_digest, copy_census_version, copy_config_digest, copy_producer_digest, parse_variant_kind, parse_variant_digest, structural_role, structural_keyword FROM policy_read_keys LIMIT 1 OFFSET (SELECT count(*) - 1 FROM policy_read_keys)",
                    [], |row| Ok(decode_read_key(row).is_err()),
                ).unwrap();
                assert!(result, "{label}: {sql}");
                connection
                    .execute_batch("ROLLBACK TO malformed; RELEASE malformed")
                    .unwrap();
            }
        }
    }

    #[test]
    fn declaration_candidates_use_the_existing_declaration_columns() {
        let key = ReadKey::lookup(
            LookupKind::DeclarationCandidates,
            LookupQuestion::Declaration {
                rel_path: "src/Registry.java".into(),
                fq_name: "fixture.Registry.register".into(),
                kind: CodeUnitType::Function,
                signature: Some("()".to_owned()),
            },
            StableDigest::sha256(b"candidates"),
        );
        let columns = ReadKeyColumns::of(&key).unwrap();
        assert_eq!(columns.family, Some("declaration_candidates"));
        assert_eq!(
            columns.decl_kind,
            Some(CodeUnitType::Function.identity_label())
        );
        assert_eq!(decode_columns(&columns).unwrap(), key);
    }

    #[test]
    fn rust_placed_declaration_round_trip_and_requires_bound_inventory() {
        let question = LookupQuestion::RustPlacedDeclaration {
            blob: [7; 20],
            declaration: u32::MAX,
            rel_path: "src/lib.rs".into(),
        };
        for placed_kind in [
            LookupKind::RustBoundTraitImplInventory,
            LookupKind::RustTraitsImplementedByInventory,
        ] {
            let key = ReadKey::lookup(
                placed_kind,
                question.clone(),
                StableDigest::sha256(b"bound inventory"),
            );
            let columns = ReadKeyColumns::of(&key).unwrap();
            assert_eq!(decode_columns(&columns).unwrap(), key);
            for kind in ALL_LOOKUP_KINDS {
                assert_eq!(
                    lookup_question_matches_kind(kind, &question),
                    matches!(
                        kind,
                        LookupKind::RustBoundTraitImplInventory
                            | LookupKind::RustTraitsImplementedByInventory
                    )
                );
            }
            for language in [None, Some("go".to_string())] {
                let mut malformed = ReadKeyColumns::of(&key).unwrap();
                malformed.languages = language;
                assert!(decode_columns(&malformed).is_err());
            }
        }
    }

    #[test]
    fn rust_inventory_questions_round_trip_and_require_rust() {
        for kind in [
            LookupKind::RustUnresolvedTraitImplInventory,
            LookupKind::RustModuleImportCandidateInventory,
            LookupKind::RustIdentifierOccurrenceInventory,
            LookupKind::RustAliasBlobInventory,
            LookupKind::RustMacroExpansionInventory,
        ] {
            let key = ReadKey::lookup(
                kind,
                LookupQuestion::Name {
                    language: Some(Language::Rust),
                    name: "Clone".into(),
                },
                StableDigest::sha256(b"inventory"),
            );
            let columns = ReadKeyColumns::of(&key).unwrap();
            assert_eq!(decode_columns(&columns).unwrap(), key);
            for language in [None, Some(Language::Go)] {
                assert!(!lookup_question_matches_kind(
                    kind,
                    &LookupQuestion::Name {
                        language,
                        name: "Clone".into(),
                    }
                ));
            }
            assert!(!lookup_question_matches_kind(
                kind,
                &LookupQuestion::File {
                    rel_path: "src/lib.rs".into(),
                }
            ));
        }
    }

    #[test]
    fn structural_inventory_questions_round_trip_through_read_columns() {
        let authority = StableDigest::sha256(b"selection");
        let answer = StableDigest::sha256(b"inventory");
        for key in [
            ReadKey::lookup(
                LookupKind::StructuralRoleNameInventory,
                LookupQuestion::StructuralRoleName {
                    language: Language::Rust,
                    role: Role::Callee,
                    name: "put".into(),
                    keyword: false,
                    authority,
                },
                answer,
            ),
            ReadKey::lookup(
                LookupKind::StructuralNameInventory,
                LookupQuestion::StructuralName {
                    language: Language::Rust,
                    name: "put".into(),
                    authority,
                },
                answer,
            ),
            ReadKey::lookup(
                LookupKind::StructuralRecoveredInventory,
                LookupQuestion::StructuralRecovered {
                    language: Language::Rust,
                    authority,
                },
                answer,
            ),
        ] {
            assert_eq!(
                decode_columns(&ReadKeyColumns::of(&key).unwrap()).unwrap(),
                key
            );
            if matches!(
                key,
                ReadKey::Lookup {
                    kind: LookupKind::StructuralRoleNameInventory,
                    ..
                }
            ) {
                let mut malformed = ReadKeyColumns::of(&key).unwrap();
                malformed.structural_role = None;
                assert!(decode_columns(&malformed).is_err());
                let mut malformed = ReadKeyColumns::of(&key).unwrap();
                malformed.structural_keyword = None;
                assert!(decode_columns(&malformed).is_err());
            } else {
                let mut malformed = ReadKeyColumns::of(&key).unwrap();
                malformed.structural_keyword = Some(1);
                assert!(decode_columns(&malformed).is_err());
            }
        }
    }

    #[test]
    fn rust_copy_absence_question_round_trips_typed_columns() {
        let key = ReadKey::lookup(
            LookupKind::RustCopyAbsence,
            LookupQuestion::RustCopyAbsence {
                owning_unit: StableDigest::sha256(b"owner"),
                target_unit: StableDigest::sha256(b"target"),
                module_path: "crate::resource".into(),
                target_identity_digest: StableDigest::sha256(b"Resource"),
                census_version: 1,
                config_digest: StableDigest::sha256(b"cfg"),
                producer_digest: StableDigest::sha256(b"producer"),
            },
            StableDigest::sha256(b"absent"),
        );
        assert_eq!(
            decode_columns(&ReadKeyColumns::of(&key).unwrap()).unwrap(),
            key
        );
        let mut malformed = ReadKeyColumns::of(&key).unwrap();
        malformed.copy_target_unit = None;
        assert!(decode_columns(&malformed).is_err());
    }

    #[test]
    fn external_selection_uses_the_lookup_columns_and_fails_closed_on_malformed_rows() {
        let key = ReadKey::lookup(
            LookupKind::ExternalSelection,
            LookupQuestion::ExternalSelection {
                question_digest: [5; 32],
            },
            StableDigest::sha256(b"external answer"),
        );
        let columns = ReadKeyColumns::of(&key).unwrap();
        assert_eq!(columns.kind, "lookup");
        assert_eq!(columns.family, Some("external_selection"));
        assert_eq!(columns.subject.as_deref(), Some([5_u8; 32].as_slice()));
        assert_eq!(decode_columns(&columns).unwrap(), key);

        let mut stray = ReadKeyColumns::of(&key).unwrap();
        stray.rel_path = Some("src/Main.java".to_owned());
        assert!(decode_columns(&stray).is_err());
        let mut missing = ReadKeyColumns::of(&key).unwrap();
        missing.subject = None;
        assert!(decode_columns(&missing).is_err());

        // A kind and a question of different shapes never pair.
        assert!(!lookup_question_matches_kind(
            LookupKind::Callers,
            &LookupQuestion::ExternalSelection {
                question_digest: [5; 32]
            }
        ));
        assert!(!lookup_question_matches_kind(
            LookupKind::ExternalSelection,
            &LookupQuestion::Summary {
                identity: StableDigest::sha256(b"summary")
            }
        ));
    }

    #[test]
    fn adding_external_selection_leaves_existing_lookup_encodings_unchanged() {
        // Digests recorded on the base commit before the variant existed.
        let answer = StableDigest::sha256(b"answer");
        let pinned = [
            (
                ReadKey::lookup(
                    LookupKind::ProcedureSummary,
                    LookupQuestion::Summary {
                        identity: StableDigest::sha256(b"summary"),
                    },
                    answer,
                ),
                "d01b2a3cf4ced479472461395d2565805dcdc60c5de8c0e07b434f3c35aa44a2",
            ),
            (
                ReadKey::lookup(
                    LookupKind::Callers,
                    LookupQuestion::File {
                        rel_path: "src/a.rs".into(),
                    },
                    answer,
                ),
                "89d9a2e0a682d9b53c5ef6794b916d7c2cc8da1256433fe2ba6f4c989e82c834",
            ),
            (
                ReadKey::lookup(
                    LookupKind::ResolvedName,
                    LookupQuestion::Name {
                        language: Some(Language::Rust),
                        name: "crate::a::f".into(),
                    },
                    answer,
                ),
                "f9f38cbc3a535e77a3f787def1df2df6c02eb799c7cc9b2f9c2e21b84c6ede3f",
            ),
        ];
        for (key, expected) in pinned {
            assert_eq!(key.canonical_digest().to_string(), expected, "{key:?}");
        }
    }

    #[test]
    fn file_receipts_preserve_legacy_encoding_and_round_trip_variants() {
        use brokk_bifrost_core::gitblob::ParseVariant;
        let oid = Oid::from_bytes(&[1; 20]).unwrap();
        let legacy = ReadKey::file(Language::Rust, "lib.rs", oid, ParseVariant::Empty);
        let columns = ReadKeyColumns::of(&legacy).unwrap();
        // Fixed base-branch canonical spelling; no optional field was present.
        assert_eq!(
            legacy.canonical_digest().to_string(),
            "8ead77b582602a575e7474157927d7c1c3ff56e55427ef0824220a9283e253aa"
        );
        assert_eq!(columns.digest, None);
        assert_eq!(columns.languages.as_deref(), Some("rust"));
        assert_eq!(columns.rel_path.as_deref(), Some("lib.rs"));
        assert_eq!(
            columns.blob_oid.as_deref(),
            Some("0101010101010101010101010101010101010101")
        );
        assert_eq!(decode_columns(&columns).unwrap(), legacy);
        let selected = ReadKey::file(
            Language::CSharp,
            "Shared.cs",
            oid,
            ParseVariant::Digest([2; 32]),
        );
        let selected_columns = ReadKeyColumns::of(&selected).unwrap();
        assert_eq!(
            selected_columns.digest.as_deref(),
            Some([2_u8; 32].as_slice())
        );
        assert_eq!(decode_columns(&selected_columns).unwrap(), selected);
        let changed = ReadKey::file(
            Language::CSharp,
            "Shared.cs",
            oid,
            ParseVariant::Digest([3; 32]),
        );
        assert_ne!(selected.canonical_digest(), changed.canonical_digest());
    }

    fn decode_columns(columns: &ReadKeyColumns) -> Result<ReadKey> {
        let connection = Connection::open_in_memory()?;
        connection
            .query_row(
                "SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19 AS copy_owning_unit, ?20, ?21, ?22, ?23, ?24, ?25, ?26 AS parse_variant_kind, ?27, ?28 AS structural_role, ?29",
                params![
                    columns.key_digest.as_slice(),
                    columns.kind,
                    columns.family,
                    columns.languages,
                    columns.rel_path,
                    columns.name,
                    columns.index_key,
                    columns.blob_oid,
                    columns.subject,
                    columns.start_byte,
                    columns.end_byte,
                    columns.digest,
                    columns.site_ordinal,
                    columns.decl_kind,
                    columns.decl_signature,
                    columns.workspace_fact_family,
                    columns.fact_member,
                    columns.fact_names,
                    columns.copy_owning_unit,
                    columns.copy_target_unit,
                    columns.copy_module_path,
                    columns.copy_target_identity_digest,
                    columns.copy_census_version,
                    columns.copy_config_digest,
                    columns.copy_producer_digest,
                    columns.parse_variant_kind,
                    columns.parse_variant_digest,
                    columns.structural_role,
                    columns.structural_keyword,
                ],
                |row| {
                    decode_read_key(row).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Blob,
                            Box::new(error),
                        )
                    })
                },
            )
            .map_err(StoreError::from)
    }

    #[test]
    fn a_dispatch_kind_cannot_reinterpret_another_question_shape() {
        let expected = ReadKey::lookup(
            LookupKind::Importers,
            LookupQuestion::File {
                rel_path: Box::from("src/Main.java"),
            },
            StableDigest::sha256(b"answer"),
        );
        let mut columns = ReadKeyColumns::of(&expected).unwrap();
        columns.family = Some(LookupKind::ProcedureDispatch.stable_label());

        let error = decode_columns(&columns).expect_err("the kind binds the question domain");
        assert!(
            error.to_string().contains("cannot carry question `file`"),
            "{error}"
        );
    }
    #[test]
    fn workspace_fact_columns_reject_inconsistent_subjects() {
        for (family, subject) in [
            (
                WorkspaceFactFamily::WorkspaceFileListing,
                FactSubject::Whole,
            ),
            (
                WorkspaceFactFamily::WorkspaceFileInventory,
                FactSubject::Whole,
            ),
            (
                WorkspaceFactFamily::WorkspaceIgnoreRules,
                FactSubject::Whole,
            ),
            (
                WorkspaceFactFamily::WorkspaceDirectory,
                FactSubject::File {
                    rel_path: "nested".into(),
                },
            ),
            (
                WorkspaceFactFamily::WorkspaceOverlayMembership,
                FactSubject::Whole,
            ),
            (
                WorkspaceFactFamily::WorkspaceOverlayMembership,
                FactSubject::File {
                    rel_path: "a.py".into(),
                },
            ),
        ] {
            let key = ReadKey::lookup(
                LookupKind::WorkspaceFact,
                LookupQuestion::WorkspaceFact {
                    family,
                    language: Language::None,
                    subject,
                },
                StableDigest::sha256(b"answer"),
            );
            assert_eq!(
                decode_columns(&ReadKeyColumns::of(&key).unwrap()).unwrap(),
                key
            );
        }
        for subject in workspace_fact_subjects() {
            let key = ReadKey::lookup(
                LookupKind::WorkspaceFact,
                LookupQuestion::WorkspaceFact {
                    family: WorkspaceFactFamily::FieldSlots,
                    language: Language::Python,
                    subject,
                },
                StableDigest::sha256(b"answer"),
            );
            assert_eq!(
                decode_columns(&ReadKeyColumns::of(&key).unwrap()).unwrap(),
                key
            );
            let mut columns = ReadKeyColumns::of(&key).unwrap();
            columns.start_byte = Some(0);
            assert!(
                decode_columns(&columns)
                    .unwrap_err()
                    .to_string()
                    .contains("unrelated question columns")
            );
        }
        let key = ReadKey::lookup(
            LookupKind::WorkspaceFact,
            LookupQuestion::WorkspaceFact {
                family: WorkspaceFactFamily::FieldSlots,
                language: Language::Python,
                subject: FactSubject::name_group_member(
                    vec!["pkg.A".into(), "pkg.B".into()],
                    "method".into(),
                ),
            },
            StableDigest::sha256(b"answer"),
        );
        for invalid in [
            "[]",
            "[1]",
            "[\"pkg.B\",\"pkg.A\"]",
            "[\"pkg.A\",\"pkg.A\"]",
            "{}",
            "not json",
        ] {
            let mut columns = ReadKeyColumns::of(&key).unwrap();
            columns.fact_names = Some(invalid.into());
            assert!(decode_columns(&columns).is_err(), "{invalid}");
        }
        let mut columns = ReadKeyColumns::of(&key).unwrap();
        columns.name = Some("unexpected owner".into());
        assert!(decode_columns(&columns).is_err());
    }
}
