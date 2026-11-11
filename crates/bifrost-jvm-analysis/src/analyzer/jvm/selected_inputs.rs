//! A request-owned view of the workspace inputs used by JVM dependency discovery.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::project::{Project, ProjectSourceSnapshot};

use super::dependency_discovery::{MAX_BUILD_METADATA_BYTES, is_discovery_manifest};

#[derive(Debug)]
pub(crate) struct SelectedInputs {
    files: Arc<BTreeSet<ProjectFile>>,
    file_set_digest: [u8; 32],
    manifests: BTreeMap<PathBuf, ManifestCapture>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::project::{
        FilesystemProject, OverlayProject, WorkspaceFileListingCache,
    };
    use std::fs;
    use tempfile::TempDir;

    fn setup() -> (TempDir, Arc<FilesystemProject>) {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("pom.xml"), "valid").unwrap();
        let root = temp.path().canonicalize().unwrap();
        let listing = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project = Arc::new(FilesystemProject::with_cached_listing(root, listing).unwrap());
        (temp, project)
    }

    /// The capture answers discovery's bounded read exactly as the live
    /// read does, at the bound and past it, for text that decodes lossily
    /// and for binary content, and retains nothing past the bound.
    #[test]
    fn captured_bounded_sources_match_live_reads() {
        let (temp, project) = setup();
        let at_bound = vec![b'a'; MAX_BUILD_METADATA_BYTES];
        let past_bound = vec![b'a'; MAX_BUILD_METADATA_BYTES + 1];
        for (name, bytes) in [
            ("nested/pom.xml", b"small".as_slice()),
            ("bound/pom.xml", at_bound.as_slice()),
            ("oversized/pom.xml", past_bound.as_slice()),
            ("invalid/pom.xml", b"\xffbad".as_slice()),
            ("binary/pom.xml", b"bin\0ary".as_slice()),
            ("buildSrc/build/libs/plugin.jar", past_bound.as_slice()),
        ] {
            let path = temp.path().join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
        // Explicit invalidation makes the new files visible to the capture.
        project.invalidate_cached_file_listing();
        let selected = capture(project.as_ref()).unwrap();
        for name in [
            "nested/pom.xml",
            "bound/pom.xml",
            "oversized/pom.xml",
            "invalid/pom.xml",
            "binary/pom.xml",
        ] {
            let file = ProjectFile::new(project.root().to_path_buf(), name);
            assert_eq!(
                selected.bounded_source(&file, MAX_BUILD_METADATA_BYTES),
                project
                    .read_source_limited(&file, MAX_BUILD_METADATA_BYTES)
                    .ok()
                    .flatten(),
                "{name}"
            );
        }
        assert!(
            !selected
                .manifests
                .contains_key(std::path::Path::new("buildSrc/build/libs/plugin.jar"))
        );
        assert!(selected.validate(project.as_ref()).is_ok());
        let overlay = OverlayProject::new(project.clone());
        assert!(overlay.set(temp.path().join("pom.xml"), "overlay".to_owned()));
        let selected = capture(&overlay).unwrap();
        let file = ProjectFile::new(project.root().to_path_buf(), "pom.xml");
        assert_eq!(
            selected.bounded_source(&file, MAX_BUILD_METADATA_BYTES),
            overlay
                .read_source_limited(&file, MAX_BUILD_METADATA_BYTES)
                .unwrap()
        );
    }

    #[test]
    fn cached_listing_misses_new_nested_manifest() {
        let (temp, project) = setup();
        let selected = capture(project.as_ref()).unwrap();
        let nested = temp.path().join("module/pom.xml");
        fs::create_dir_all(nested.parent().unwrap()).unwrap();
        fs::write(nested, "new").unwrap();
        assert!(matches!(
            selected.validate(project.as_ref()),
            Err(CaptureDrift::FileSet(_))
        ));
    }

    #[test]
    fn validation_distinguishes_listing_manifest_and_absence_drift() {
        let (temp, project) = setup();
        let selected = capture(project.as_ref()).unwrap();
        fs::write(temp.path().join("pom.xml"), "other").unwrap();
        assert!(
            matches!(selected.validate(project.as_ref()), Err(CaptureDrift::Manifest(path)) if path == std::path::Path::new("pom.xml"))
        );

        fs::write(temp.path().join("pom.xml"), "valid").unwrap();
        fs::write(temp.path().join("unlisted.txt"), "x").unwrap();
        assert!(matches!(
            selected.validate(project.as_ref()),
            Err(CaptureDrift::FileSet(path)) if path == std::path::Path::new(".")
        ));

        fs::remove_file(temp.path().join("unlisted.txt")).unwrap();
        fs::write(temp.path().join("settings.xml"), "x").unwrap();
        assert!(
            matches!(selected.validate(project.as_ref()), Err(CaptureDrift::Absence(path)) if path == std::path::Path::new("settings.xml"))
        );
    }
}

/// One manifest as discovery's bounded read sees it.
#[derive(Debug)]
pub(crate) enum ManifestCapture {
    Present(ProjectSourceSnapshot),
    /// Oversized, binary or unreadable: discovery's bounded read answers
    /// nothing for it, and the selection records it as a partial manifest.
    Unread,
    Absent,
}

/// Discovery reads a manifest through the same bounded read and treats an
/// oversized or unreadable one as unread, so a read error is that answer
/// rather than a capture failure. Only the bounded bytes are retained.
fn read_manifest(project: &dyn Project, file: &ProjectFile) -> ManifestCapture {
    match project.read_source_snapshot_limited(file, MAX_BUILD_METADATA_BYTES) {
        Ok(Some(snapshot)) => ManifestCapture::Present(snapshot),
        Ok(None) | Err(_) => ManifestCapture::Unread,
    }
}

#[derive(Debug)]
pub(crate) enum CaptureDrift {
    FileSet(PathBuf),
    Manifest(PathBuf),
    Absence(PathBuf),
    Read(PathBuf, io::Error),
}

fn digest(files: &BTreeSet<ProjectFile>) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-jvm-selected-file-set:v1");
    hash.sequence("files", &files.iter().collect::<Vec<_>>(), |hash, file| {
        hash.field(
            "path",
            brokk_bifrost_core::path_utils::rel_path_string(file).as_bytes(),
        );
    });
    hash.finish()
}

/// Capture the listing and the bytes of every manifest discovery reads.
/// Other dependency inputs, such as `buildSrc` sources, are fenced by the
/// listing only: metadata discovery never reads them, and the build tools
/// that do read them from disk themselves, which keeps tool modes
/// uncertified.
pub(crate) fn capture(project: &dyn Project) -> io::Result<SelectedInputs> {
    let files = project.all_files_shared()?;
    let mut manifests = BTreeMap::new();
    for file in files.iter().filter(|file| is_discovery_manifest(file)) {
        manifests.insert(file.rel_path().to_path_buf(), read_manifest(project, file));
    }
    for path in [
        "pom.xml",
        "settings.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "gradle.properties",
        "gradle.lockfile",
        "gradle/libs.versions.toml",
        "gradle/wrapper/gradle-wrapper.properties",
        ".mvn/maven.config",
        ".mvn/jvm.config",
        ".mvn/extensions.xml",
        ".mvn/wrapper/maven-wrapper.properties",
    ] {
        let path = PathBuf::from(path);
        if !files.contains(&ProjectFile::new(
            project.root().to_path_buf(),
            path.clone(),
        )) {
            manifests.insert(path, ManifestCapture::Absent);
        }
    }
    Ok(SelectedInputs {
        file_set_digest: digest(&files),
        files,
        manifests,
    })
}

impl super::dependency_discovery::DiscoveryInputs for SelectedInputs {
    fn files(&self) -> io::Result<Arc<BTreeSet<ProjectFile>>> {
        self.files()
    }

    fn bounded_source(&self, file: &ProjectFile, max_bytes: usize) -> Option<String> {
        self.bounded_source(file, max_bytes)
    }
}

impl SelectedInputs {
    pub(crate) fn files(&self) -> io::Result<Arc<BTreeSet<ProjectFile>>> {
        Ok(Arc::clone(&self.files))
    }

    pub(crate) fn bounded_source(&self, file: &ProjectFile, max_bytes: usize) -> Option<String> {
        assert_eq!(
            max_bytes, MAX_BUILD_METADATA_BYTES,
            "the capture holds manifests read at discovery's bound"
        );
        debug_assert!(is_discovery_manifest(file));
        let captured = self.manifests.get(file.rel_path());
        debug_assert!(
            captured.is_some(),
            "discovery read outside captured manifests"
        );
        match captured? {
            ManifestCapture::Present(snapshot) => Some(snapshot.source().to_owned()),
            ManifestCapture::Unread | ManifestCapture::Absent => None,
        }
    }

    pub(crate) fn validate(&self, project: &dyn Project) -> Result<(), CaptureDrift> {
        let current = project
            .authoritative_files()
            .map_err(|error| CaptureDrift::Read(PathBuf::from("."), error))?;
        for (path, capture) in &self.manifests {
            if matches!(capture, ManifestCapture::Absent)
                && current.iter().any(|file| file.rel_path() == path)
            {
                return Err(CaptureDrift::Absence(path.clone()));
            }
        }
        if digest(&current) != self.file_set_digest {
            return Err(CaptureDrift::FileSet(PathBuf::from(".")));
        }
        for (path, capture) in &self.manifests {
            if matches!(capture, ManifestCapture::Absent) {
                continue;
            }
            let file = ProjectFile::new(project.root().to_path_buf(), path.clone());
            let unchanged = match (capture, read_manifest(project, &file)) {
                (ManifestCapture::Present(captured), ManifestCapture::Present(current)) => {
                    captured.oid() == current.oid()
                }
                (ManifestCapture::Unread, ManifestCapture::Unread) => true,
                _ => false,
            };
            if !unchanged {
                return Err(CaptureDrift::Manifest(path.clone()));
            }
        }
        Ok(())
    }
}
