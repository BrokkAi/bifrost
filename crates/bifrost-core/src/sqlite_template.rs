//! Empty-database templates in the machine cache.
//!
//! Creating an empty Bifrost database means running its whole schema: over a
//! thousand CREATE statements for the analyzer store, and twenty migrations for
//! the semantic-pack catalog. Every disposable store and catalog paid that,
//! which made it the largest fixed cost of an analyzer-backed test. A database
//! file that does not exist yet is instead copied from a template, which the
//! first such database for a schema builds through its ordinary fresh path.
//!
//! Each kind of database is a family. A family's template is named
//! `<family>-template-<version>-<digest>.db`, where the digest covers the
//! family's schema inputs and the SQLite version. A family removes only its
//! own stale templates.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

/// Directory under the machine cache root that holds the templates. A
/// template is machine-wide state, not a workspace cache, so it lives under the
/// machine cache root even when `BIFROST_CACHE_DIR` places a workspace's store
/// elsewhere.
pub const TEMPLATE_DIR_NAME: &str = "store-templates";

/// Another schema's template is removed once it is this old. An age, not the
/// schema, decides: builds of different schemas can run side by side, and each
/// would otherwise remove the other's template and rebuild its own on every
/// database it creates.
const STALE_TEMPLATE_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// The template directory, or `None` when this machine has no cache root.
pub fn template_dir() -> Option<PathBuf> {
    crate::gitblob::machine_cache_dir().map(|root| root.join(TEMPLATE_DIR_NAME))
}

/// One family's template for one schema.
pub struct Template {
    family: &'static str,
    file_name: String,
}

impl Template {
    /// `schema_inputs` must cover everything that decides the bytes of an
    /// empty database of this family other than the SQLite library, which is
    /// added here.
    pub fn new(family: &'static str, version: i64, schema_inputs: &[&[u8]]) -> Self {
        let mut hasher = Sha256::new();
        for field in schema_inputs
            .iter()
            .copied()
            .chain([rusqlite::version().as_bytes()])
        {
            hasher.update((field.len() as u64).to_le_bytes());
            hasher.update(field);
        }
        let digest = crate::analyzer::canonical_hash::lower_hex_string(&hasher.finalize().into());
        Self {
            family,
            file_name: format!("{}{version}-{digest}.db", family_prefix(family)),
        }
    }

    pub fn file_name(&self) -> &str {
        &self.file_name
    }
}

/// Every file of `family` in the template directory starts with this prefix,
/// including staging files that a crash left behind.
fn family_prefix(family: &str) -> String {
    format!("{family}-template-")
}

/// A file operation on a template or a seeded database failed.
#[derive(Debug)]
pub struct TemplateIoError {
    pub operation: &'static str,
    pub path: PathBuf,
    pub source: std::io::Error,
}

impl fmt::Display for TemplateIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {}: {}",
            self.operation,
            self.path.display(),
            self.source
        )
    }
}

impl From<TemplateIoError> for String {
    fn from(error: TemplateIoError) -> Self {
        error.to_string()
    }
}

fn io_error(
    operation: &'static str,
    path: &Path,
) -> impl FnOnce(std::io::Error) -> TemplateIoError {
    let path = path.to_path_buf();
    move |source| TemplateIoError {
        operation,
        path,
        source,
    }
}

/// Create a database that does not exist yet by copying its family's template.
///
/// When the template is missing, `build` creates an empty current-schema
/// database at the path it is given, through the family's ordinary fresh
/// path, and that database is published as the template. It is built in
/// `db_path`'s directory, which has passed the caller's filesystem checks;
/// SQLite never opens a file in the template directory. `build` must leave a
/// complete database in the main file, with no WAL to replay.
///
/// Returns whether this call created the database. It returns `false` when the
/// database already exists, when another process created it first, and when
/// there is no template directory.
pub fn seed_missing_database<E: From<TemplateIoError>>(
    db_path: &Path,
    template_dir: Option<&Path>,
    template: &Template,
    build: impl FnOnce(&Path) -> Result<(), E>,
) -> Result<bool, E> {
    let Some(template_dir) = template_dir else {
        return Ok(false);
    };
    if db_path
        .try_exists()
        .map_err(io_error("checking", db_path))?
    {
        return Ok(false);
    }
    let parent = db_path
        .parent()
        .expect("a database path has a parent directory");
    let staged = tempfile::Builder::new()
        .prefix(".bifrost-seed")
        .tempfile_in(parent)
        .map_err(io_error("staging a database in", parent))?
        .into_temp_path();
    let template_path = template_dir.join(template.file_name());
    match std::fs::copy(&template_path, &staged) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            build(&staged)?;
            publish_template(&staged, template_dir, &template_path, template.family)?;
        }
        Err(error) => return Err(io_error("copying", &template_path)(error).into()),
    }
    match staged.persist_noclobber(db_path) {
        Ok(()) => Ok(true),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(io_error("creating", db_path)(error.error).into()),
    }
}

/// Copy a freshly built database into the template directory as `template`.
fn publish_template(
    built: &Path,
    template_dir: &Path,
    template: &Path,
    family: &str,
) -> Result<(), TemplateIoError> {
    std::fs::create_dir_all(template_dir).map_err(io_error("creating", template_dir))?;
    let family_prefix = family_prefix(family);
    let staged = tempfile::Builder::new()
        .prefix(&format!("{family_prefix}staging"))
        .tempfile_in(template_dir)
        .map_err(io_error("staging a template in", template_dir))?
        .into_temp_path();
    std::fs::copy(built, &staged).map_err(io_error("copying", built))?;
    match staged.persist_noclobber(template) {
        Ok(()) => {
            if let Err(error) = remove_stale_templates(template_dir, &family_prefix, template) {
                eprintln!("Bifrost template cleanup skipped: {error}");
            }
            Ok(())
        }
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(io_error("creating", template)(error.error)),
    }
}

fn remove_stale_templates(
    template_dir: &Path,
    family_prefix: &str,
    current: &Path,
) -> Result<(), TemplateIoError> {
    let entries = std::fs::read_dir(template_dir).map_err(io_error("reading", template_dir))?;
    for entry in entries {
        let entry = entry.map_err(io_error("reading", template_dir))?;
        let path = entry.path();
        if path == current
            || !entry
                .file_name()
                .to_string_lossy()
                .starts_with(family_prefix)
        {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .map_err(io_error("reading", &path))?;
        // A modification time in the future reads as new, not stale.
        if modified.elapsed().unwrap_or_default() < STALE_TEMPLATE_AGE {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error("removing", &path)(error)),
        }
    }
    Ok(())
}
