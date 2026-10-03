//! One parsed, content-owned Cargo manifest for Rust consumers.
//!
//! Cargo configuration is selected by the caller before it reaches this
//! crate.  This document keeps the exact bytes and their content identity
//! beside the parsed TOML value so naming, route discovery, and selected
//! operation projections cannot silently parse different representations of
//! one manifest.

use git2::{ObjectType, Oid};

/// The exact selected Cargo manifest and its structured TOML document.
///
/// The TOML value is intentionally private. Language-owned consumers borrow
/// the structured fields through this module while the source bytes and OID
/// remain tied to the same parse. Callers that need a normalized projection
/// should derive it from this document rather than parsing the source again.
#[derive(Clone, Debug)]
pub struct RustCargoManifestDocument {
    source_bytes: Box<[u8]>,
    content_oid: Oid,
    value: toml::Value,
}

impl PartialEq for RustCargoManifestDocument {
    fn eq(&self, other: &Self) -> bool {
        self.content_oid == other.content_oid && self.source_bytes == other.source_bytes
    }
}

impl Eq for RustCargoManifestDocument {}

impl RustCargoManifestDocument {
    /// Parse exact UTF-8 manifest bytes and compute their Git blob identity.
    pub fn from_source_bytes(source_bytes: Box<[u8]>) -> Result<Self, String> {
        let content_oid =
            Oid::hash_object(ObjectType::Blob, &source_bytes).map_err(|error| error.to_string())?;
        Self::from_retained_source(content_oid, source_bytes)
    }

    /// Parse source text while retaining the bytes that produced the parse.
    pub fn from_source(source: &str) -> Result<Self, String> {
        Self::from_source_bytes(source.as_bytes().to_vec().into_boxed_slice())
    }

    /// Rehydrate a document from bytes retained under a content OID.
    pub fn from_retained_source(content_oid: Oid, source_bytes: Box<[u8]>) -> Result<Self, String> {
        let actual_oid =
            Oid::hash_object(ObjectType::Blob, &source_bytes).map_err(|error| error.to_string())?;
        if actual_oid != content_oid {
            return Err(format!(
                "retained Cargo manifest bytes hash to {actual_oid}, expected {content_oid}"
            ));
        }
        let source = std::str::from_utf8(&source_bytes)
            .map_err(|error| format!("retained Cargo manifest bytes are not UTF-8: {error}"))?;
        let value =
            toml::from_str(source).map_err(|error| format!("invalid Cargo manifest: {error}"))?;
        Ok(Self {
            source_bytes,
            content_oid,
            value,
        })
    }

    /// Exact bytes used to compute [`Self::content_oid`] and parse the value.
    pub fn source_bytes(&self) -> &[u8] {
        &self.source_bytes
    }

    /// Content identity of the exact retained bytes.
    pub fn content_oid(&self) -> Oid {
        self.content_oid
    }

    pub(crate) fn get(&self, key: &str) -> Option<&toml::Value> {
        self.value.get(key)
    }

    /// The package name as Cargo spells it, when this manifest declares one.
    pub fn package_name(&self) -> Option<&str> {
        self.get("package")?.get("name")?.as_str()
    }

    /// The library target name as Cargo spells it when the manifest declares
    /// one. An implicit library inherits the package name and is handled by
    /// the caller after this method returns `None`.
    pub fn library_name(&self) -> Option<&str> {
        self.get("lib")?.get("name")?.as_str()
    }

    /// Explicit library source path, or Cargo's default path when absent.
    pub(crate) fn library_path(&self) -> Result<&std::path::Path, &'static str> {
        match self.get("lib").and_then(|library| library.get("path")) {
            Some(toml::Value::String(path)) => Ok(std::path::Path::new(path)),
            Some(_) => Err("Cargo lib.path must be a string"),
            None => Ok(std::path::Path::new("src/lib.rs")),
        }
    }

    /// The normalized library target name when the manifest declares one.
    pub(crate) fn normalized_library_name(&self) -> Option<String> {
        self.library_name().map(normalize_crate_name)
    }

    /// Digest of everything in this manifest that crate topology, crate
    /// naming or dependency routes can read.
    ///
    /// It hashes the parsed document, so comments and formatting do not
    /// reach it, and table key order does not either. It leaves out only what
    /// no Rust reader consumes: `[profile]`, `[badges]`, `metadata` tables, and
    /// the publishing fields of `[package]` and `[workspace.package]`
    /// (description, version, and the like). Everything else counts, so a
    /// field a reader starts consuming later is covered without a change
    /// here.
    pub fn topology_digest(&self) -> [u8; 32] {
        use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;

        #[derive(Clone, Copy)]
        enum Table {
            Root,
            Package,
            Workspace,
            Other,
        }
        const PUBLISHING: &[&str] = &[
            "authors",
            "categories",
            "default-run",
            "description",
            "documentation",
            "exclude",
            "homepage",
            "include",
            "keywords",
            "license",
            "license-file",
            "metadata",
            "publish",
            "readme",
            "repository",
            "rust-version",
            "version",
        ];
        let inert = |table: Table, key: &str| match table {
            Table::Root => matches!(key, "profile" | "badges"),
            Table::Package => PUBLISHING.contains(&key),
            Table::Workspace => key == "metadata",
            Table::Other => false,
        };
        let mut hasher = CanonicalHasher::new(b"cargo manifest topology");
        let mut stack = vec![(Table::Root, &self.value)];
        while let Some((table, value)) = stack.pop() {
            match value {
                toml::Value::Table(entries) => {
                    let mut keys = entries
                        .keys()
                        .filter(|key| !inert(table, key))
                        .collect::<Vec<_>>();
                    keys.sort();
                    hasher.field("table", &(keys.len() as u64).to_be_bytes());
                    for key in &keys {
                        hasher.value(key.as_bytes());
                    }
                    // Pushed in reverse so they are hashed in key order.
                    for key in keys.into_iter().rev() {
                        let child = match (table, key.as_str()) {
                            (Table::Root, "package") => Table::Package,
                            (Table::Root, "workspace") => Table::Workspace,
                            (Table::Workspace, "package") => Table::Package,
                            _ => Table::Other,
                        };
                        stack.push((child, &entries[key.as_str()]));
                    }
                }
                toml::Value::Array(items) => {
                    hasher.field("array", &(items.len() as u64).to_be_bytes());
                    stack.extend(items.iter().rev().map(|item| (Table::Other, item)));
                }
                toml::Value::String(text) => hasher.field("string", text.as_bytes()),
                toml::Value::Integer(number) => hasher.field("integer", &number.to_be_bytes()),
                toml::Value::Float(number) => {
                    hasher.field("float", &number.to_bits().to_be_bytes())
                }
                toml::Value::Boolean(flag) => hasher.field("boolean", &[u8::from(*flag)]),
                toml::Value::Datetime(datetime) => {
                    hasher.field("datetime", datetime.to_string().as_bytes())
                }
            }
        }
        hasher.finish()
    }
}

pub(crate) fn normalize_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_exact_bytes_and_borrowed_package_identity() {
        let source = b"[package]\nname = \"dashed-package\"\n\n[lib]\nname = \"dashed_lib\"\n"
            .to_vec()
            .into_boxed_slice();
        let document = RustCargoManifestDocument::from_source_bytes(source.clone())
            .expect("manifest document");

        assert_eq!(document.source_bytes(), source.as_ref());
        assert_eq!(document.package_name(), Some("dashed-package"));
        assert_eq!(document.library_name(), Some("dashed_lib"));
        assert_eq!(
            document.normalized_library_name(),
            Some("dashed_lib".to_string())
        );
        assert_eq!(
            document.content_oid(),
            Oid::hash_object(ObjectType::Blob, &source).unwrap()
        );
    }

    #[test]
    fn retained_bytes_must_match_their_content_oid() {
        let source = b"[package]\nname = \"one\"\n".to_vec().into_boxed_slice();
        let other = b"[package]\nname = \"two\"\n".to_vec().into_boxed_slice();
        let oid = Oid::hash_object(ObjectType::Blob, &source).expect("source oid");

        let error = RustCargoManifestDocument::from_retained_source(oid, other)
            .expect_err("mismatched retained bytes");
        assert!(error.contains("expected"), "{error}");
    }

    const TOPOLOGY_BASE: &str = "[package]\nname = \"app\"\nedition = \"2021\"\n\
        [dependencies]\ndep = { path = \"../dep\", features = [\"a\"] }\n\
        [features]\ndefault = [\"x\"]\nx = []\n\
        [workspace]\nmembers = [\"one\"]\n\
        [workspace.package]\nedition = \"2021\"\n";

    fn topology_digest(source: &str) -> [u8; 32] {
        RustCargoManifestDocument::from_source(source)
            .expect("manifest document")
            .topology_digest()
    }

    #[test]
    fn topology_digest_ignores_what_no_rust_reader_consumes() {
        let base = topology_digest(TOPOLOGY_BASE);
        for edited in [
            format!("# comment\n{TOPOLOGY_BASE}"),
            TOPOLOGY_BASE.replace(
                "name = \"app\"\nedition = \"2021\"",
                "edition = \"2021\"\nname   =   \"app\"",
            ),
            TOPOLOGY_BASE.replace(
                "[package]\n",
                "[package]\nversion = \"9.9.9\"\ndescription = \"d\"\nauthors = [\"a\"]\n",
            ),
            TOPOLOGY_BASE.replace(
                "[workspace.package]\n",
                "[workspace.package]\nversion = \"1.0.0\"\nlicense = \"MIT\"\n",
            ),
            format!(
                "{TOPOLOGY_BASE}[profile.release]\nopt-level = 3\n[badges]\nmaintenance = {{ status = \"x\" }}\n"
            ),
            format!(
                "{TOPOLOGY_BASE}[package.metadata.docs]\nall = true\n[workspace.metadata.tool]\nk = 1\n"
            ),
        ] {
            assert_eq!(topology_digest(&edited), base, "{edited}");
        }
    }

    #[test]
    fn topology_digest_follows_what_crate_rows_and_routes_read() {
        let base = topology_digest(TOPOLOGY_BASE);
        for edited in [
            TOPOLOGY_BASE.replace("name = \"app\"", "name = \"app2\""),
            TOPOLOGY_BASE.replace("edition = \"2021\"\n[dep", "edition = \"2018\"\n[dep"),
            TOPOLOGY_BASE.replace("../dep", "../other"),
            TOPOLOGY_BASE.replace("features = [\"a\"]", "features = [\"b\"]"),
            TOPOLOGY_BASE.replace("default = [\"x\"]", "default = []"),
            TOPOLOGY_BASE.replace("members = [\"one\"]", "members = [\"one\", \"two\"]"),
            TOPOLOGY_BASE.replace(
                "[workspace.package]\nedition = \"2021\"",
                "[workspace.package]\nedition = \"2024\"",
            ),
            format!("{TOPOLOGY_BASE}[lib]\npath = \"src/other.rs\"\n"),
            format!("{TOPOLOGY_BASE}[[bin]]\nname = \"tool\"\npath = \"src/tool.rs\"\n"),
            format!("{TOPOLOGY_BASE}[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n"),
            format!("{TOPOLOGY_BASE}[patch.crates-io]\ndep = {{ path = \"../dep\" }}\n"),
        ] {
            assert_ne!(topology_digest(&edited), base, "{edited}");
        }
    }
}
