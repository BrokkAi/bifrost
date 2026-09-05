//! Lossless analyzer-store columns for one recorded [`ReadKey`].
//!
//! Persisted derived products use the same read vocabulary and must rebuild
//! the exact structured key before verification. Keeping that encoding here
//! makes adding a new [`ReadKey`] variant an exhaustive-match compile error for
//! every store client instead of letting two product tables drift.

use git2::Oid;

use super::{Result, StoreError};
use crate::analyzer::Language;
use crate::analyzer::content_identity::WorkspaceContentIdentity;
use crate::analyzer::invalidation::{DerivedArtifactId, DerivedArtifactKind};
use crate::analyzer::read_ledger::{
    CallSiteLocator, IndexFamily, LookupKind, LookupQuestion, ReadKey,
};
use crate::analyzer::semantic::ids::StableDigest;

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
    pub(super) index_key: Option<Vec<u8>>,
    pub(super) blob_oid: Option<String>,
    pub(super) subject: Option<Vec<u8>>,
    pub(super) start_byte: Option<i64>,
    pub(super) end_byte: Option<i64>,
    pub(super) digest: Option<Vec<u8>>,
}

impl ReadKeyColumns {
    /// Encode one key by exhaustively projecting its structured fields.
    pub(super) fn of(key: &ReadKey) -> Self {
        let mut columns = Self {
            key_digest: *key.canonical_digest().as_bytes(),
            kind: key.stable_label(),
            family: None,
            languages: None,
            rel_path: None,
            name: None,
            index_key: None,
            blob_oid: None,
            subject: None,
            start_byte: None,
            end_byte: None,
            digest: None,
        };
        match key {
            ReadKey::File {
                language,
                rel_path,
                blob,
            } => {
                columns.languages = Some(language.config_label().to_string());
                columns.rel_path = Some(rel_path.to_string());
                columns.blob_oid = Some(blob.to_string());
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
                columns.family = Some(kind.stable_label());
                columns.digest = Some(digest.as_bytes().to_vec());
                match question {
                    LookupQuestion::Declaration { rel_path, fq_name } => {
                        columns.rel_path = Some(rel_path.to_string());
                        columns.name = Some(fq_name.to_string());
                    }
                    LookupQuestion::File { rel_path } => {
                        columns.rel_path = Some(rel_path.to_string());
                    }
                    LookupQuestion::CallSite {
                        rel_path,
                        artifact,
                        site,
                    } => {
                        columns.rel_path = Some(rel_path.to_string());
                        columns.subject = Some(artifact.as_bytes().to_vec());
                        columns.start_byte = Some(site.start_byte as i64);
                        columns.end_byte = Some(site.end_byte as i64);
                    }
                    LookupQuestion::Summary { identity } => {
                        columns.subject = Some(identity.as_bytes().to_vec());
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
        columns
    }
}

/// Rebuild one read key from normalized columns and verify its stored digest.
///
/// `row` must select `key_digest`, `kind`, `family`, `languages`, `rel_path`,
/// `name`, `index_key`, `blob_oid`, `subject`, `start_byte`, `end_byte`, and
/// `digest`, in that order. Comparing the rebuilt key's canonical digest with
/// `key_digest` turns column fidelity into a checked store invariant.
pub(super) fn decode_read_key(row: &rusqlite::Row<'_>) -> Result<ReadKey> {
    let key_digest = row.get::<_, Vec<u8>>(0)?;
    let kind = row.get::<_, String>(1)?;
    let family = row.get::<_, Option<String>>(2)?;
    let languages = row.get::<_, Option<String>>(3)?;
    let rel_path = row.get::<_, Option<String>>(4)?;
    let name = row.get::<_, Option<String>>(5)?;
    let index_key = row.get::<_, Option<Vec<u8>>>(6)?;
    let blob_oid = row.get::<_, Option<String>>(7)?;
    let subject = row.get::<_, Option<Vec<u8>>>(8)?;
    let start_byte = row.get::<_, Option<i64>>(9)?;
    let end_byte = row.get::<_, Option<i64>>(10)?;
    let digest = row.get::<_, Option<Vec<u8>>>(11)?;

    let missing = |column: &str| StoreError::new(format!("read key `{kind}` has no {column}"));
    let key = match kind.as_str() {
        "file" => ReadKey::File {
            language: decode_language(languages.as_deref().ok_or_else(|| missing("language"))?)?,
            rel_path: Box::from(rel_path.ok_or_else(|| missing("path"))?.as_str()),
            blob: decode_oid(&blob_oid.ok_or_else(|| missing("blob"))?)?,
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
            let lookup_kind = lookup_kind_of(family.as_deref().ok_or_else(|| missing("kind"))?)?;
            let question = match (rel_path, name, subject, start_byte, end_byte) {
                (Some(rel_path), Some(fq_name), None, None, None) => LookupQuestion::Declaration {
                    rel_path: Box::from(rel_path.as_str()),
                    fq_name: Box::from(fq_name.as_str()),
                },
                (Some(rel_path), None, None, None, None) => LookupQuestion::File {
                    rel_path: Box::from(rel_path.as_str()),
                },
                (Some(rel_path), None, Some(artifact), Some(start), Some(end)) => {
                    LookupQuestion::CallSite {
                        rel_path: Box::from(rel_path.as_str()),
                        artifact: decode_digest(&artifact, "call site artifact")?,
                        site: CallSiteLocator {
                            start_byte: start as usize,
                            end_byte: end as usize,
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
            };
            ReadKey::Lookup {
                kind: lookup_kind,
                question,
                digest: decode_digest(&digest.ok_or_else(|| missing("answer"))?, "lookup answer")?,
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
        return Err(StoreError::new(format!(
            "read key `{kind}` did not rebuild to its stored identity {}",
            hex_of(&key_digest)
        )));
    }
    Ok(key)
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
    Language::from_config_label(label)
        .filter(|language| language.config_label() == label)
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
const ALL_LOOKUP_KINDS: [LookupKind; 8] = [
    LookupKind::Callers,
    LookupKind::Callees,
    LookupKind::Usages,
    LookupKind::Importers,
    LookupKind::ReferenceCandidates,
    LookupKind::Descendants,
    LookupKind::Dispatch,
    LookupKind::ProcedureSummary,
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
mod tests {
    use rusqlite::{Connection, params};

    use super::*;

    fn decode_columns(columns: &ReadKeyColumns) -> Result<ReadKey> {
        let connection = Connection::open_in_memory()?;
        connection
            .query_row(
                "SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12",
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

    fn every_read_key_shape() -> Vec<ReadKey> {
        let answer = StableDigest::sha256(b"answer");
        vec![
            ReadKey::file(
                Language::Java,
                "src/Main.java",
                "1111111111111111111111111111111111111111"
                    .parse()
                    .expect("valid object id"),
            ),
            ReadKey::path_absent(Language::Java, "src/Missing.java"),
            ReadKey::index(IndexFamily::DefinitionExact, b"com.example.Main"),
            ReadKey::lookup(
                LookupKind::Callers,
                LookupQuestion::Declaration {
                    rel_path: Box::from("src/Main.java"),
                    fq_name: Box::from("com.example.Main#run"),
                },
                answer,
            ),
            ReadKey::lookup(
                LookupKind::Importers,
                LookupQuestion::File {
                    rel_path: Box::from("src/Main.java"),
                },
                answer,
            ),
            ReadKey::lookup(
                LookupKind::Dispatch,
                LookupQuestion::CallSite {
                    rel_path: Box::from("src/Main.java"),
                    artifact: StableDigest::sha256(b"artifact"),
                    site: CallSiteLocator {
                        start_byte: 10,
                        end_byte: 24,
                    },
                },
                answer,
            ),
            ReadKey::lookup(
                LookupKind::ProcedureSummary,
                LookupQuestion::Summary {
                    identity: StableDigest::sha256(b"summary"),
                },
                answer,
            ),
            ReadKey::artifact(
                DerivedArtifactId::semantic_artifact(StableDigest::sha256(b"ir")),
                Some("src/Main.java"),
            ),
            ReadKey::artifact(
                DerivedArtifactId::new(
                    DerivedArtifactKind::WorkspaceUsageGraph,
                    StableDigest::sha256(b"graph"),
                ),
                None,
            ),
            ReadKey::scope(
                [Language::Java, Language::Go],
                WorkspaceContentIdentity::from_digest(StableDigest::sha256(b"scope")),
            ),
            ReadKey::Models(StableDigest::sha256(b"models")),
            ReadKey::Policy {
                semantic_hash: StableDigest::sha256(b"policy"),
                source: StableDigest::sha256(b"source"),
            },
            ReadKey::Configuration(StableDigest::sha256(b"configuration")),
            ReadKey::Epoch(StableDigest::sha256(b"epoch")),
        ]
    }

    #[test]
    fn every_read_key_shape_round_trips_through_shared_columns() {
        for expected in every_read_key_shape() {
            let actual = decode_columns(&ReadKeyColumns::of(&expected)).unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn a_corrupt_canonical_digest_is_rejected() {
        let expected = ReadKey::Models(StableDigest::sha256(b"models"));
        let mut columns = ReadKeyColumns::of(&expected);
        columns.key_digest = *StableDigest::sha256(b"other").as_bytes();

        let error = decode_columns(&columns).expect_err("the digest must bind every column");
        assert!(error.to_string().contains("did not rebuild"), "{error}");
    }
}
