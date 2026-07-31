use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use super::CatalogError;

pub(super) fn prepare_root(root: &Path) -> Result<PathBuf, CatalogError> {
    reject_symlink(root, "catalog root")?;
    fs::create_dir_all(root).map_err(|error| CatalogError::io("create catalog root", error))?;
    let root = root
        .canonicalize()
        .map_err(|error| CatalogError::io("canonicalize catalog root", error))?;
    for directory in [
        root.join("objects"),
        root.join("objects/sha256"),
        root.join("staging"),
    ] {
        reject_symlink(&directory, "catalog directory")?;
        fs::create_dir_all(&directory)
            .map_err(|error| CatalogError::io("create catalog directory", error))?;
    }
    reject_symlink(
        &root.join(super::db::CATALOG_DB_FILE_NAME),
        "catalog database",
    )?;
    Ok(root)
}

pub(super) fn open_read_only_root(root: &Path) -> Result<PathBuf, CatalogError> {
    reject_symlink(root, "catalog root")?;
    let root = root
        .canonicalize()
        .map_err(|error| CatalogError::io("canonicalize catalog root", error))?;
    for path in [
        root.join("objects"),
        root.join("objects/sha256"),
        root.join(super::db::CATALOG_DB_FILE_NAME),
    ] {
        reject_symlink(&path, "catalog path")?;
    }
    Ok(root)
}

pub(super) fn publish(
    root: &Path,
    digest: &str,
    bytes: &[u8],
) -> Result<(PathBuf, bool), CatalogError> {
    validate_digest(digest)?;
    if sha256(bytes) != digest {
        return Err(CatalogError::Integrity(
            "object bytes do not match their stored digest".to_owned(),
        ));
    }
    let relative = relative_object_path(digest);
    let destination = root.join(&relative);
    let parent = destination
        .parent()
        .expect("digest object path always has a parent");
    reject_object_tree(root, parent)?;
    fs::create_dir_all(parent)
        .map_err(|error| CatalogError::io("create object prefix directory", error))?;
    reject_symlink(&destination, "catalog object")?;
    if destination.exists() {
        verify(&destination, digest, bytes.len() as u64)?;
        return Ok((relative, false));
    }

    let staging = root.join("staging");
    let mut temporary = NamedTempFile::new_in(&staging)
        .map_err(|error| CatalogError::io("create staged object", error))?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|error| CatalogError::io("write staged object", error))?;
    match temporary.persist_noclobber(&destination) {
        Ok(_) => Ok((relative, true)),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            verify(&destination, digest, bytes.len() as u64)?;
            Ok((relative, false))
        }
        Err(error) => Err(CatalogError::io("publish staged object", error.error)),
    }
}

pub(super) fn read(
    root: &Path,
    relative: &str,
    digest: &str,
    stored_size: u64,
) -> Result<Vec<u8>, CatalogError> {
    validate_digest(digest)?;
    let expected = relative_object_path(digest);
    if Path::new(relative) != expected {
        return Err(CatalogError::Integrity(
            "catalog object path does not match its digest".to_owned(),
        ));
    }
    let path = root.join(expected);
    reject_object_tree(
        root,
        path.parent()
            .expect("digest object path always has a prefix directory"),
    )?;
    reject_symlink(&path, "catalog object")?;
    verify(&path, digest, stored_size)?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(stored_size)
            .map_err(|_| CatalogError::Integrity("stored size exceeds usize".to_owned()))?,
    );
    File::open(&path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|error| CatalogError::io("read catalog object", error))?;
    Ok(bytes)
}

pub(super) fn delete(root: &Path, relative: &str, digest: &str) -> Result<bool, CatalogError> {
    validate_digest(digest)?;
    let expected = relative_object_path(digest);
    if Path::new(relative) != expected {
        return Err(CatalogError::Integrity(
            "catalog object path does not match its digest".to_owned(),
        ));
    }
    let path = root.join(expected);
    reject_object_tree(
        root,
        path.parent()
            .expect("digest object path always has a prefix directory"),
    )?;
    reject_symlink(&path, "catalog object")?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(CatalogError::io("delete catalog object", error)),
    }
}

fn verify(path: &Path, digest: &str, stored_size: u64) -> Result<(), CatalogError> {
    let metadata =
        fs::metadata(path).map_err(|error| CatalogError::io("stat catalog object", error))?;
    if !metadata.is_file() || metadata.len() != stored_size {
        return Err(CatalogError::Integrity(format!(
            "catalog object size mismatch for {digest}"
        )));
    }
    let bytes = fs::read(path).map_err(|error| CatalogError::io("verify catalog object", error))?;
    if sha256(&bytes) != digest {
        return Err(CatalogError::Integrity(format!(
            "catalog object digest mismatch for {digest}"
        )));
    }
    Ok(())
}

fn relative_object_path(digest: &str) -> PathBuf {
    Path::new("objects")
        .join("sha256")
        .join(&digest[..2])
        .join(&digest[2..])
}

fn validate_digest(digest: &str) -> Result<(), CatalogError> {
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(CatalogError::Integrity(
            "catalog digest must be lowercase SHA-256 hex".to_owned(),
        ))
    }
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

fn reject_object_tree(root: &Path, prefix: &Path) -> Result<(), CatalogError> {
    for path in [root.join("objects"), root.join("objects/sha256")] {
        reject_symlink(&path, "catalog object directory")?;
    }
    reject_symlink(prefix, "object prefix directory")
}

fn reject_symlink(path: &Path, label: &str) -> Result<(), CatalogError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(CatalogError::Integrity(format!(
            "refusing to use symlinked {label}: {}",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CatalogError::io("inspect catalog path", error)),
    }
}
