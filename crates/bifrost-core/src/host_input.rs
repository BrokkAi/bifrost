//! Open explicit host-owned input without traversing symbolic links.
//!
//! This is a filesystem primitive, not an approval mechanism. Consumers still
//! authenticate the opened bytes and check their own root/ownership boundary.

use std::fs::File;
use std::io;
use std::path::Path;

/// Hold directory descriptors while walking an absolute normalized host path,
/// so a concurrent rename/symlink replacement cannot redirect a checked prefix.
/// The final descriptor must be a regular file; opening a FIFO must not block.
pub fn open_regular_file_without_symlinks(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "host input path must be absolute",
        ));
    }
    let file = open_without_symlinks(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "host input must be a regular file",
        ));
    }
    Ok(file)
}

#[cfg(unix)]
fn open_without_symlinks(path: &Path) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    let mut directory = File::open("/")?;
    let mut components = path.components().skip(1).peekable();
    while let Some(component) = components.next() {
        if !matches!(component, Component::Normal(_)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "host input path must be normalized",
            ));
        }
        let name = CString::new(component.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "host input path contains NUL")
        })?;
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | if components.peek().is_some() {
                libc::O_DIRECTORY
            } else {
                libc::O_NONBLOCK
            };
        // SAFETY: directory is a live descriptor, name is NUL-terminated, and
        // O_CREAT is absent so no variadic mode argument is required.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a fresh owned descriptor. Replacing directory
        // closes the previous prefix only after the child has been opened.
        directory = unsafe { File::from_raw_fd(fd) };
    }
    Ok(directory)
}

#[cfg(windows)]
fn open_without_symlinks(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    let mut prefix = std::path::PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        // A verbatim drive prefix (\\?\C:) is not a complete filesystem path
        // until the following root separator has been appended.
        if matches!(component, std::path::Component::Prefix(_)) {
            continue;
        }
        if std::fs::symlink_metadata(&prefix)?.file_attributes() & 0x400 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "host input path must not contain reparse points",
            ));
        }
    }
    // FILE_FLAG_OPEN_REPARSE_POINT: inspect the final object itself, not a link.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(0x0020_0000)
        .open(path)?;
    if file.metadata()?.file_attributes() & 0x400 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "host input must not be a reparse point",
        ));
    }
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn open_without_symlinks(_path: &Path) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "host input no-symlink opening is unavailable on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_only_a_regular_absolute_host_file() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let path = root.join("input");
        std::fs::write(&path, b"host input").unwrap();
        assert_eq!(
            open_regular_file_without_symlinks(&path)
                .unwrap()
                .metadata()
                .unwrap()
                .len(),
            10
        );
        assert!(open_regular_file_without_symlinks(&root).is_err());
        assert!(open_regular_file_without_symlinks(Path::new("input")).is_err());
    }

    #[cfg(windows)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#14134: Windows verbatim drive prefixes were inspected before their root separator"
    )]
    fn opens_a_canonical_verbatim_host_file() {
        use std::io::Read;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("host-input");
        std::fs::write(&path, b"verified host input").unwrap();
        let canonical = path.canonicalize().unwrap();
        assert!(matches!(
            canonical.components().next(),
            Some(std::path::Component::Prefix(_))
        ));
        let mut file = open_regular_file_without_symlinks(&canonical).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "verified host input");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_both_leaf_and_ancestor_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let path = root.join("input");
        std::fs::write(&path, b"host input").unwrap();
        let leaf = root.join("link");
        std::os::unix::fs::symlink(&path, &leaf).unwrap();
        assert!(open_regular_file_without_symlinks(&leaf).is_err());
        let ancestor = root.join("alias");
        std::os::unix::fs::symlink(&root, &ancestor).unwrap();
        assert!(open_regular_file_without_symlinks(&ancestor.join("input")).is_err());
    }
}
