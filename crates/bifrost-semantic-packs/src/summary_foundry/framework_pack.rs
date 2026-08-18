//! Convert the framework declaration candidates into activatable
//! `declaration_facts` packs so the framework types that anchor the OWASP
//! Benchmark taint sources and sinks resolve `external_indexed` (#1935, the
//! type-resolution prerequisite).
//!
//! The Benchmark/FIRD bakeoff abstains upstream of propagation because the
//! servlet and JDBC types that anchor the sources and sinks are unresolved. A
//! `declaration_facts` pack that publishes those types answers a written
//! `HttpServletRequest` or `PreparedStatement` from the activated overlay, which
//! is what makes a name resolve at the external boundary instead of staying
//! unknown.
//!
//! # Candidate shape
//!
//! Each candidate file is one artifact's declarations: an `artifact` string, a
//! `provenance` string, and a `types` array. Each type carries the [`TypeFact`]
//! fields plus a nested `members` array of [`MemberFact`], each member keyed to
//! its type by `owner`. The shipped [`AuthoredPayload::DeclarationFacts`] holds
//! flat `types` and `members` vectors, so the converter splits every type into
//! its own [`TypeFact`] and lifts its members into the pack's flat member list;
//! the `owner` link the candidate already records is preserved untouched.
//!
//! # The kept hierarchy (servlet supertype members)
//!
//! `HttpServletRequest extends ServletRequest`, and the shared getters
//! (`getParameter`, `getHeader`, ...) are recorded on `ServletRequest`. The
//! converter keeps that hierarchy faithfully rather than flattening the
//! inherited members onto `HttpServletRequest`, because declaration-facts
//! resolution follows supertype members for external types: the compiled
//! `extends` fact becomes an overlay relation, and
//! `SemanticModelOverlay::owner_surface` closes over it, so
//! `JvmExternalDeclarationIndex::resolve_member_spelling` reaches an inherited
//! `getParameter` on `HttpServletRequest` through the closure and reports it at
//! its declaring type. Flattening would duplicate every inherited member onto
//! every subtype and lose the declaring-type identity; keeping the hierarchy is
//! both smaller and faithful.
//!
//! # Pinning
//!
//! One pack per artifact, because the pack schema pins one artifact per pack.
//! The `java.lang` and `java.sql` candidates carry the `jdk` artifact and ship
//! as one pack pinned on the `jdk` toolchain, the same real pin the JDK
//! declaration pack uses. The servlet candidate targets the Maven coordinate
//! `javax.servlet:javax.servlet-api:4.0.1`; a byte-level `artifact_sha256` pin
//! needs the jar, which this generation step cannot fetch, so the servlet pack
//! is generated but staged under `staged/` with the coordinate and version
//! recorded and no faked digest.
//!
//! The conversion is a deterministic function of the candidate content: two runs
//! produce byte-identical pack sources and audit report, with no clock.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use brokk_bifrost_analysis::analyzer::semantic_model::{
    ActivationSelector, AuthoredPayload, AuthoredSemanticModelPack, AuthoredShard, Compatibility,
    CompilerOptions, Completeness, MemberFact, NameSelector, Producer, Provenance, Safety,
    SourceFormat, TypeFact, VersionConstraint, compile_source,
};
use serde::{Deserialize, Serialize};

use super::sanitizer_pack::summary_id;

/// The audit-report format tag. Bump it when a consumer must read the file
/// differently, not when a field is added.
pub const FRAMEWORK_PACK_AUDIT_FORMAT: &str = "bifrost_framework_pack_audit/v1";

/// The audit report's file name, written beside the packs.
pub const FRAMEWORK_AUDIT_FILE_NAME: &str = "rejects.json";

/// The producer name recorded in every generated pack.
const PRODUCER_NAME: &str = "bifrost-framework-foundry";

/// The framework foundry's own version, advanced when the converter changes the
/// shape of its output. It is deliberately not the crate version: the checked-in
/// packs are gated on byte equality with this generator, and reading the crate
/// version would break that gate at every release bump without any content
/// change. `golden_pack.rs` states the same rule; #1871 applied it there and
/// left this converter behind, which is what made
/// `the_checked_in_packs_match_the_generator` fail at v0.10.3.
const PRODUCER_VERSION: &str = "0.9.0";

/// The pack content version. It is the framework content's own version, not the
/// Bifrost version, and advances when the shipped declarations change.
const PACK_CONTENT_VERSION: &str = "0.1.0";

/// The Bifrost compatibility requirement every generated pack declares.
const BIFROST_REQUIREMENT: &str = ">=0.8.0, <0.11.0";

/// The authored framework declarations are Bifrost's own recorded surface,
/// not a slice of the described library. New Bifrost-owned public packs use
/// the public project license; retained packs may declare their own provenance
/// and license in their checked-in metadata.
const PACK_LICENSE: &str = "Apache-2.0";

/// The JDK toolchain requirement. Every claimed type (`Runtime`, `Statement`,
/// `PreparedStatement`, ...) exists in Java 17 and later.
const JDK_TOOLCHAIN_REQUIREMENT: &str = ">=17.0.0";

/// The declaration packs are a curated subset of each library's types, so the
/// pack envelope is partial: a member-absence proof over one of these types must
/// not read the recorded surface as exhaustive.
const PACK_COMPLETENESS: Completeness = Completeness::Partial;

/// The one artifact string that names the JDK rather than a Maven coordinate.
const JDK_ARTIFACT: &str = "jdk";

/// One framework candidate file: one artifact's declarations.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrameworkDeclFile {
    artifact: String,
    #[allow(dead_code)]
    provenance: String,
    /// Each entry is a [`TypeFact`] object with an extra nested `members` array.
    /// It is read as a raw object so the `members` field can be split off before
    /// the remainder is deserialized as a strict [`TypeFact`].
    types: Vec<serde_json::Value>,
}

/// One generated pack: its identity, whether it is byte-pinned, and its source
/// text ready to write and to compile through the production compiler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedFrameworkPack {
    pub pack_id: String,
    /// The artifact the pack pins: `"jdk"` or a Maven coordinate.
    pub artifact: String,
    /// The path under the output root, so the writer keeps staged packs apart
    /// from the pinned one without a second decision.
    pub relative_path: PathBuf,
    /// A pinned pack activates on a concrete artifact identity (the JDK
    /// toolchain). A staged pack carries the coordinate but no byte-level
    /// `artifact_sha256`, because the jar is not available here to digest.
    pub pinned: bool,
    /// The pack source JSON, pretty-printed with a trailing newline. This is the
    /// exact checked-in bytes and the exact input to `compile_source`.
    pub source_json: String,
}

/// One generated pack's audit line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrameworkPackAudit {
    pub pack_id: String,
    pub artifact: String,
    pub pinned: bool,
    pub ecosystem: String,
    pub completeness: Completeness,
    pub types: usize,
    pub members: usize,
    /// Why a pack is staged rather than pinned, recorded so the staging decision
    /// is auditable. Absent for a pinned pack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staged_reason: Option<String>,
}

/// The structured audit report written beside the packs as `rejects.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrameworkAuditReport {
    pub format: String,
    pub types_total: usize,
    pub members_total: usize,
    pub packs: Vec<FrameworkPackAudit>,
}

/// The full conversion outcome: the generated packs and the audit report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkConversion {
    pub packs: Vec<GeneratedFrameworkPack>,
    pub audit: FrameworkAuditReport,
}

/// Why a conversion could not complete. These are converter or candidate-shape
/// failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameworkPackError {
    ReadDir {
        path: PathBuf,
        message: String,
    },
    ReadFile {
        path: PathBuf,
        message: String,
    },
    Parse {
        path: PathBuf,
        message: String,
    },
    /// A candidate type object was not a JSON object, so its members could not be
    /// split off.
    TypeNotObject {
        artifact: String,
    },
    MalformedArtifact {
        artifact: String,
    },
    /// A generated pack did not survive the production compiler. That is a
    /// converter or candidate bug: the report lists the diagnostics.
    CompileFailed {
        pack_id: String,
        diagnostics: Vec<String>,
    },
}

impl fmt::Display for FrameworkPackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadDir { path, message } => {
                write!(
                    formatter,
                    "cannot read directory {}: {message}",
                    path.display()
                )
            }
            Self::ReadFile { path, message } => {
                write!(formatter, "cannot read {}: {message}", path.display())
            }
            Self::Parse { path, message } => {
                write!(formatter, "cannot parse {}: {message}", path.display())
            }
            Self::TypeNotObject { artifact } => write!(
                formatter,
                "a type in artifact `{artifact}` is not a JSON object"
            ),
            Self::MalformedArtifact { artifact } => write!(
                formatter,
                "artifact `{artifact}` is neither `jdk` nor a `group:artifact:version` coordinate"
            ),
            Self::CompileFailed {
                pack_id,
                diagnostics,
            } => write!(
                formatter,
                "generated pack `{pack_id}` failed the production compiler: {diagnostics:?}"
            ),
        }
    }
}

impl std::error::Error for FrameworkPackError {}

/// Read every `*.json` candidate file under `candidates_dir`, group by artifact,
/// and produce the pack sources plus the audit report.
pub fn convert_framework_candidates(
    candidates_dir: &Path,
) -> Result<FrameworkConversion, FrameworkPackError> {
    let by_artifact = read_candidates(candidates_dir)?;
    build_conversion(by_artifact)
}

/// Write the generated pack sources and the audit report under `output_root`,
/// pinned packs at the root and staged packs under `staged/`. Returns the
/// written paths in sorted order.
pub fn write_framework_packs(
    conversion: &FrameworkConversion,
    output_root: &Path,
) -> Result<Vec<PathBuf>, FrameworkPackError> {
    let mut written = Vec::new();
    for pack in &conversion.packs {
        let path = output_root.join(&pack.relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| FrameworkPackError::ReadDir {
                path: parent.to_owned(),
                message: error.to_string(),
            })?;
        }
        fs::write(&path, pack.source_json.as_bytes()).map_err(|error| {
            FrameworkPackError::ReadFile {
                path: path.clone(),
                message: error.to_string(),
            }
        })?;
        written.push(path);
    }
    let audit_path = output_root.join(FRAMEWORK_AUDIT_FILE_NAME);
    fs::write(&audit_path, serialize_audit(&conversion.audit).as_bytes()).map_err(|error| {
        FrameworkPackError::ReadFile {
            path: audit_path.clone(),
            message: error.to_string(),
        }
    })?;
    written.push(audit_path);
    written.sort();
    Ok(written)
}

/// The flattened types and members of one artifact.
#[derive(Default)]
struct ArtifactDeclarations {
    types: Vec<TypeFact>,
    members: Vec<MemberFact>,
}

/// Read the candidate files in a stable order and group their declarations by
/// artifact. Files are read in sorted name order; artifacts are grouped in
/// sorted order.
fn read_candidates(
    candidates_dir: &Path,
) -> Result<BTreeMap<String, ArtifactDeclarations>, FrameworkPackError> {
    let mut files = Vec::new();
    let read_dir = fs::read_dir(candidates_dir).map_err(|error| FrameworkPackError::ReadDir {
        path: candidates_dir.to_owned(),
        message: error.to_string(),
    })?;
    for entry in read_dir {
        let entry = entry.map_err(|error| FrameworkPackError::ReadDir {
            path: candidates_dir.to_owned(),
            message: error.to_string(),
        })?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
            files.push(path);
        }
    }
    files.sort();

    let mut by_artifact: BTreeMap<String, ArtifactDeclarations> = BTreeMap::new();
    for path in files {
        let bytes = fs::read(&path).map_err(|error| FrameworkPackError::ReadFile {
            path: path.clone(),
            message: error.to_string(),
        })?;
        let file: FrameworkDeclFile =
            serde_json::from_slice(&bytes).map_err(|error| FrameworkPackError::Parse {
                path: path.clone(),
                message: error.to_string(),
            })?;
        let declarations = by_artifact.entry(file.artifact.clone()).or_default();
        for type_value in file.types {
            let (type_fact, members) = split_type(&file.artifact, type_value, &path)?;
            declarations.types.push(type_fact);
            declarations.members.extend(members);
        }
    }
    Ok(by_artifact)
}

/// Split one candidate type object into its own [`TypeFact`] and its nested
/// [`MemberFact`] list. The member `owner` link is already recorded in the
/// candidate and is carried through untouched.
fn split_type(
    artifact: &str,
    value: serde_json::Value,
    path: &Path,
) -> Result<(TypeFact, Vec<MemberFact>), FrameworkPackError> {
    let serde_json::Value::Object(mut object) = value else {
        return Err(FrameworkPackError::TypeNotObject {
            artifact: artifact.to_owned(),
        });
    };
    let members_value = object
        .remove("members")
        .unwrap_or_else(|| serde_json::Value::Array(Vec::new()));
    let members: Vec<MemberFact> =
        serde_json::from_value(members_value).map_err(|error| FrameworkPackError::Parse {
            path: path.to_owned(),
            message: error.to_string(),
        })?;
    let type_fact: TypeFact =
        serde_json::from_value(serde_json::Value::Object(object)).map_err(|error| {
            FrameworkPackError::Parse {
                path: path.to_owned(),
                message: error.to_string(),
            }
        })?;
    Ok((type_fact, members))
}

fn build_conversion(
    by_artifact: BTreeMap<String, ArtifactDeclarations>,
) -> Result<FrameworkConversion, FrameworkPackError> {
    let mut packs = Vec::new();
    let mut pack_audits = Vec::new();
    let mut types_total = 0usize;
    let mut members_total = 0usize;

    for (artifact, mut declarations) in by_artifact {
        // Sort by declaration id for byte-stable output. The owner link is by
        // id, so member order is independent of it.
        declarations
            .types
            .sort_by(|left, right| left.id.cmp(&right.id));
        declarations
            .members
            .sort_by(|left, right| left.id.cmp(&right.id));
        types_total = types_total.saturating_add(declarations.types.len());
        members_total = members_total.saturating_add(declarations.members.len());

        let identity = PackIdentity::for_artifact(&artifact)?;
        let types_count = declarations.types.len();
        let members_count = declarations.members.len();
        let pack = identity.build_pack(declarations.types, declarations.members);
        let source_json = serialize_pack(&pack);
        compile_check(&identity.pack_id, &source_json)?;

        pack_audits.push(FrameworkPackAudit {
            pack_id: identity.pack_id.clone(),
            artifact: artifact.clone(),
            pinned: identity.pinned,
            ecosystem: identity.ecosystem.clone(),
            completeness: PACK_COMPLETENESS,
            types: types_count,
            members: members_count,
            staged_reason: identity.staged_reason.clone(),
        });
        packs.push(GeneratedFrameworkPack {
            pack_id: identity.pack_id.clone(),
            artifact,
            relative_path: identity.relative_path(),
            pinned: identity.pinned,
            source_json,
        });
    }

    packs.sort_by(|left, right| left.pack_id.cmp(&right.pack_id));
    pack_audits.sort_by(|left, right| left.pack_id.cmp(&right.pack_id));

    let audit = FrameworkAuditReport {
        format: FRAMEWORK_PACK_AUDIT_FORMAT.to_owned(),
        types_total,
        members_total,
        packs: pack_audits,
    };
    Ok(FrameworkConversion { packs, audit })
}

/// The identity of one pack: its id, ecosystem, activation, and whether it is
/// byte-pinned.
struct PackIdentity {
    pack_id: String,
    ecosystem: String,
    pinned: bool,
    activation: ActivationSelector,
    toolchains: Vec<VersionConstraint>,
    provenance_source: String,
    staged_reason: Option<String>,
}

impl PackIdentity {
    fn for_artifact(artifact: &str) -> Result<Self, FrameworkPackError> {
        if artifact == JDK_ARTIFACT {
            return Ok(Self {
                pack_id: "bifrost.jdk-framework-decls".to_owned(),
                ecosystem: "jdk".to_owned(),
                pinned: true,
                activation: ActivationSelector {
                    package: None,
                    module: None,
                    toolchain: Some(NameSelector {
                        name: "jdk".to_owned(),
                        version: Some(JDK_TOOLCHAIN_REQUIREMENT.to_owned()),
                    }),
                    targets: vec!["jvm".to_owned()],
                    configurations: Vec::new(),
                    artifact_sha256: None,
                },
                toolchains: vec![VersionConstraint {
                    name: "jdk".to_owned(),
                    requirement: JDK_TOOLCHAIN_REQUIREMENT.to_owned(),
                }],
                provenance_source: "hand-authored JDK framework declarations (java.lang, java.sql)"
                    .to_owned(),
                staged_reason: None,
            });
        }

        // A Maven coordinate `group:artifact:version`. The package name is
        // `group:artifact`; the artifact id becomes the pack slug and the
        // version becomes the package version requirement.
        let parts: Vec<&str> = artifact.split(':').collect();
        if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
            return Err(FrameworkPackError::MalformedArtifact {
                artifact: artifact.to_owned(),
            });
        }
        let package_name = format!("{}:{}", parts[0], parts[1]);
        let version = format!("={}", parts[2]);
        let slug = summary_id(parts[1]);
        Ok(Self {
            pack_id: format!("bifrost.{slug}-framework-decls"),
            ecosystem: "maven".to_owned(),
            // Staged: the coordinate and version are named, but the byte-level
            // artifact digest is not produced here, so the pack is not shipped on
            // a faked pin.
            pinned: false,
            activation: ActivationSelector {
                package: Some(NameSelector {
                    name: package_name,
                    version: Some(version),
                }),
                module: None,
                toolchain: None,
                targets: vec!["jvm".to_owned()],
                configurations: Vec::new(),
                artifact_sha256: None,
            },
            toolchains: Vec::new(),
            provenance_source: format!("hand-authored framework declarations over {artifact}"),
            staged_reason: Some(format!(
                "byte-level artifact_sha256 for {artifact} needs the jar, which this generation \
                 step cannot fetch; the coordinate and version are pinned, the digest is not"
            )),
        })
    }

    fn relative_path(&self) -> PathBuf {
        let file_name = format!("{}.json", self.pack_id);
        if self.pinned {
            PathBuf::from(file_name)
        } else {
            Path::new("staged").join(file_name)
        }
    }

    fn build_pack(
        &self,
        types: Vec<TypeFact>,
        members: Vec<MemberFact>,
    ) -> AuthoredSemanticModelPack {
        AuthoredSemanticModelPack {
            schema_version: 1,
            pack_id: self.pack_id.clone(),
            version: PACK_CONTENT_VERSION.to_owned(),
            producer: Producer {
                name: PRODUCER_NAME.to_owned(),
                version: PRODUCER_VERSION.to_owned(),
            },
            language: "java".to_owned(),
            ecosystem: self.ecosystem.clone(),
            compatibility: Compatibility {
                bifrost: BIFROST_REQUIREMENT.to_owned(),
                toolchains: self.toolchains.clone(),
            },
            provenance: Provenance {
                source: self.provenance_source.clone(),
                revision: Some("framework-decls".to_owned()),
            },
            license: PACK_LICENSE.to_owned(),
            completeness: PACK_COMPLETENESS,
            safety: Safety {
                generated_code_only: false,
                review_required: true,
            },
            shards: vec![AuthoredShard {
                id: format!("declarations.{}", self.ecosystem),
                activation: vec![self.activation.clone()],
                payload: AuthoredPayload::DeclarationFacts {
                    types,
                    members,
                    relations: Vec::new(),
                },
            }],
        }
    }
}

/// Serialize a pack to canonical pretty JSON with a trailing newline.
fn serialize_pack(pack: &AuthoredSemanticModelPack) -> String {
    let mut json = serde_json::to_string_pretty(pack).expect("a pack is serializable");
    json.push('\n');
    json
}

/// Compile a generated pack through the production compiler. A failure is a
/// converter or candidate bug, so it is raised rather than recorded.
fn compile_check(pack_id: &str, source_json: &str) -> Result<(), FrameworkPackError> {
    compile_source(
        SourceFormat::Json,
        source_json.as_bytes(),
        &CompilerOptions::default(),
    )
    .map(|_| ())
    .map_err(|diagnostics| FrameworkPackError::CompileFailed {
        pack_id: pack_id.to_owned(),
        diagnostics: diagnostics
            .iter()
            .map(|diagnostic| format!("{diagnostic:?}"))
            .collect(),
    })
}

/// Serialize the audit report to canonical pretty JSON with a trailing newline.
pub fn serialize_audit(audit: &FrameworkAuditReport) -> String {
    let mut json = serde_json::to_string_pretty(audit).expect("the audit report is serializable");
    json.push('\n');
    json
}

#[cfg(test)]
mod tests {
    use super::*;

    fn convert(files: &[(&str, &str)]) -> FrameworkConversion {
        let dir = tempfile::tempdir().expect("temp candidates dir");
        for (name, body) in files {
            fs::write(dir.path().join(name), body).expect("write candidate file");
        }
        convert_framework_candidates(dir.path()).expect("conversion")
    }

    const SERVLET: &str = r#"{
      "artifact": "javax.servlet:javax.servlet-api:4.0.1",
      "provenance": "javadoc",
      "types": [
        {
          "id": "servlet.servletrequest",
          "name": "javax.servlet.ServletRequest",
          "type_kind": "interface",
          "visibility": "public",
          "is_abstract": true,
          "type_parameters": [],
          "hierarchy": [],
          "aliases": [],
          "extension_surfaces": [],
          "locator": {"kind": "artifact", "path": "javax/servlet/ServletRequest.java", "symbol": "javax.servlet.ServletRequest"},
          "members": [
            {
              "id": "member.servletrequest.getparameter",
              "owner": "servlet.servletrequest",
              "name": "getParameter",
              "member_kind": "method",
              "visibility": "public",
              "is_abstract": true,
              "is_virtual": true,
              "signature": {"parameters": [{"name": "name", "type": {"kind": "named", "name": "java.lang.String"}}], "returns": {"kind": "named", "name": "java.lang.String"}},
              "aliases": [],
              "locator": {"kind": "artifact", "path": "javax/servlet/ServletRequest.java", "symbol": "getParameter(java.lang.String)"}
            }
          ]
        },
        {
          "id": "servlet.httpservletrequest",
          "name": "javax.servlet.http.HttpServletRequest",
          "type_kind": "interface",
          "visibility": "public",
          "is_abstract": true,
          "type_parameters": [],
          "hierarchy": [{"hierarchy_kind": "extends", "target": {"kind": "named", "name": "javax.servlet.ServletRequest"}}],
          "aliases": [],
          "extension_surfaces": [],
          "locator": {"kind": "artifact", "path": "javax/servlet/http/HttpServletRequest.java", "symbol": "javax.servlet.http.HttpServletRequest"},
          "members": []
        }
      ]
    }"#;

    const JDK: &str = r#"{
      "artifact": "jdk",
      "provenance": "javadoc",
      "types": [
        {
          "id": "jdk.statement",
          "name": "java.sql.Statement",
          "type_kind": "interface",
          "visibility": "public",
          "is_abstract": true,
          "type_parameters": [],
          "hierarchy": [{"hierarchy_kind": "extends", "target": {"kind": "named", "name": "java.lang.AutoCloseable"}}],
          "aliases": [],
          "extension_surfaces": [],
          "locator": {"kind": "artifact", "path": "java.sql/java/sql/Statement.java", "symbol": "java.sql.Statement"},
          "members": [
            {
              "id": "member.statement.executequery",
              "owner": "jdk.statement",
              "name": "executeQuery",
              "member_kind": "method",
              "visibility": "public",
              "is_abstract": true,
              "is_virtual": true,
              "signature": {"parameters": [{"name": "sql", "type": {"kind": "named", "name": "java.lang.String"}}], "returns": {"kind": "named", "name": "java.sql.ResultSet"}},
              "aliases": [],
              "locator": {"kind": "artifact", "path": "java.sql/java/sql/Statement.java", "symbol": "executeQuery(java.lang.String)"}
            }
          ]
        }
      ]
    }"#;

    #[test]
    fn the_jdk_artifact_produces_a_pinned_toolchain_pack() {
        let conversion = convert(&[("java.sql.json", JDK)]);
        let pack = conversion
            .packs
            .iter()
            .find(|pack| pack.pack_id == "bifrost.jdk-framework-decls")
            .expect("the JDK pack ships");
        assert!(pack.pinned, "the JDK pack is pinned by its toolchain");
        assert_eq!(
            pack.relative_path,
            PathBuf::from("bifrost.jdk-framework-decls.json")
        );
        // The nested member is lifted into the flat member list under its owner.
        let value: serde_json::Value = serde_json::from_str(&pack.source_json).unwrap();
        let payload = &value["shards"][0]["payload"];
        assert_eq!(payload["types"].as_array().unwrap().len(), 1);
        assert_eq!(payload["members"].as_array().unwrap().len(), 1);
        assert_eq!(payload["members"][0]["owner"], "jdk.statement");
        assert!(payload["types"][0].get("members").is_none());
    }

    #[test]
    fn the_servlet_coordinate_is_staged_unpinned_with_a_recorded_reason() {
        let conversion = convert(&[("servlet.json", SERVLET)]);
        let pack = conversion
            .packs
            .iter()
            .find(|pack| pack.pack_id.contains("servlet"))
            .expect("the servlet pack ships");
        assert!(!pack.pinned, "the servlet pack is staged unpinned");
        assert!(pack.relative_path.starts_with("staged"));
        let audit = conversion
            .audit
            .packs
            .iter()
            .find(|entry| entry.pack_id == pack.pack_id)
            .unwrap();
        assert!(audit.staged_reason.is_some());
        // The kept `extends` hierarchy is carried onto HttpServletRequest so the
        // inherited getParameter resolves through the supertype closure.
        let value: serde_json::Value = serde_json::from_str(&pack.source_json).unwrap();
        let types = value["shards"][0]["payload"]["types"].as_array().unwrap();
        let http = types
            .iter()
            .find(|fact| fact["name"] == "javax.servlet.http.HttpServletRequest")
            .unwrap();
        assert_eq!(http["hierarchy"][0]["hierarchy_kind"], "extends");
        assert_eq!(
            http["hierarchy"][0]["target"]["name"],
            "javax.servlet.ServletRequest"
        );
    }

    #[test]
    fn conversion_is_deterministic() {
        let first = convert(&[("jdk.json", JDK), ("servlet.json", SERVLET)]);
        let second = convert(&[("jdk.json", JDK), ("servlet.json", SERVLET)]);
        assert_eq!(first, second);
    }
}
