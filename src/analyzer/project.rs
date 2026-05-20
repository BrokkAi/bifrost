use crate::analyzer::{Language, ProjectFile};
use ignore::WalkBuilder;
use std::collections::{BTreeSet, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use walkdir::WalkDir;

pub trait Project: Send + Sync {
    fn root(&self) -> &Path;
    fn analyzer_languages(&self) -> BTreeSet<Language>;
    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>>;
    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>>;
    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile>;

    fn is_gitignored(&self, _rel_path: &Path) -> bool {
        false
    }

    /// Read the source text of `file`. Default reads from disk. The LSP server
    /// overrides this via `OverlayProject` to serve unsaved buffer content
    /// pushed in by `textDocument/did{Open,Change}` notifications.
    fn read_source(&self, file: &ProjectFile) -> io::Result<String> {
        file.read_to_string()
    }

    /// True when an in-memory overlay is shadowing `file`'s disk content.
    /// Analyzer persistence consults this to skip baseline writes for files
    /// whose parsed state was computed against unsaved content — otherwise the
    /// on-disk mtime would not change but the baseline row would be wrong.
    fn has_overlay(&self, _file: &ProjectFile) -> bool {
        false
    }
}

#[derive(Debug, Clone)]
pub struct TestProject {
    root: PathBuf,
    languages: BTreeSet<Language>,
}

impl TestProject {
    pub fn new(root: impl Into<PathBuf>, language: Language) -> Self {
        Self::with_languages(root, BTreeSet::from([language]))
    }

    pub fn with_languages(root: impl Into<PathBuf>, languages: BTreeSet<Language>) -> Self {
        let root = root.into();
        assert!(root.is_absolute(), "test project root must be absolute");
        assert!(root.is_dir(), "test project root must exist");
        assert!(
            !languages.is_empty(),
            "test project must contain at least one analyzer language"
        );

        Self { root, languages }
    }

    pub fn from_root_with_inferred_languages(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        assert!(root.is_absolute(), "test project root must be absolute");
        assert!(root.is_dir(), "test project root must exist");

        let languages = detect_languages(&root)?;
        if languages.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "test project root contains no supported analyzer files: {}",
                    root.display()
                ),
            ));
        }

        Ok(Self { root, languages })
    }

    pub fn root_path(&self) -> &Path {
        &self.root
    }
}

impl Project for TestProject {
    fn root(&self) -> &Path {
        &self.root
    }

    fn analyzer_languages(&self) -> BTreeSet<Language> {
        self.languages.clone()
    }

    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
        let mut files = BTreeSet::new();

        for entry in WalkDir::new(&self.root) {
            let entry = entry?;
            if !entry.file_type().is_file() {
                continue;
            }

            let rel = entry
                .path()
                .strip_prefix(&self.root)
                .expect("walkdir returned a path outside the project root");
            files.insert(ProjectFile::new(self.root.clone(), rel.to_path_buf()));
        }

        Ok(files)
    }

    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
        let extensions = language.extensions();
        if extensions.is_empty() {
            return Ok(BTreeSet::new());
        }

        let files = self.all_files()?;
        Ok(files
            .into_iter()
            .filter(|file| {
                file.rel_path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| extensions.contains(&ext))
                    .unwrap_or(false)
            })
            .collect())
    }

    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
        let file = ProjectFile::new(self.root.clone(), rel_path.to_path_buf());
        file.exists().then_some(file)
    }
}

#[derive(Debug, Clone)]
pub struct FilesystemProject {
    root: PathBuf,
    languages: BTreeSet<Language>,
}

impl FilesystemProject {
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into().canonicalize()?;
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("project root is not a directory: {}", root.display()),
            ));
        }

        let languages = detect_languages(&root)?;
        Ok(Self { root, languages })
    }

    pub fn root_path(&self) -> &Path {
        &self.root
    }
}

impl Project for FilesystemProject {
    fn root(&self) -> &Path {
        &self.root
    }

    fn analyzer_languages(&self) -> BTreeSet<Language> {
        self.languages.clone()
    }

    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
        collect_project_files(&self.root)
    }

    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
        let extensions = language.extensions();
        if extensions.is_empty() {
            return Ok(BTreeSet::new());
        }

        let files = self.all_files()?;
        Ok(files
            .into_iter()
            .filter(|file| {
                file.rel_path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| {
                        let normalized = ext.to_ascii_lowercase();
                        extensions.contains(&normalized.as_str())
                    })
                    .unwrap_or(false)
            })
            .collect())
    }

    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
        let file = ProjectFile::new(self.root.clone(), rel_path.to_path_buf());
        file.exists().then_some(file)
    }

    fn is_gitignored(&self, rel_path: &Path) -> bool {
        let file = ProjectFile::new(self.root.clone(), rel_path.to_path_buf());
        file.exists()
            && self
                .all_files()
                .map(|files| !files.contains(&file))
                .unwrap_or(false)
    }
}

fn collect_project_files(root: &Path) -> io::Result<BTreeSet<ProjectFile>> {
    let mut files = BTreeSet::new();
    let walker = WalkBuilder::new(root)
        .hidden(false)
        .ignore(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .parents(true)
        .require_git(false)
        .build();

    for entry in walker {
        let entry = entry.map_err(|err| io::Error::other(err.to_string()))?;
        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }

        let rel = entry
            .path()
            .strip_prefix(root)
            .expect("walkdir returned a path outside the project root");
        files.insert(ProjectFile::new(root.to_path_buf(), rel.to_path_buf()));
    }

    Ok(files)
}

/// A [`Project`] wrapper that layers an in-memory content overlay on top of a
/// delegate project. Reads consult the overlay first and fall back to the
/// delegate; every other [`Project`] method (file enumeration, language
/// detection) is delegated unchanged. Used by the LSP server to feed
/// `textDocument/did{Open,Change}` buffer content into the analyzer without
/// writing to disk.
pub struct OverlayProject {
    delegate: Arc<dyn Project>,
    overlays: Arc<RwLock<HashMap<PathBuf, String>>>,
}

impl OverlayProject {
    pub fn new(delegate: Arc<dyn Project>) -> Self {
        Self {
            delegate,
            overlays: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Replace (or insert) the overlay for `abs_path`.
    pub fn set(&self, abs_path: PathBuf, content: String) {
        self.overlays
            .write()
            .expect("overlay lock poisoned")
            .insert(abs_path, content);
    }

    /// Remove an overlay, if present. Returns `true` when an overlay was
    /// actually removed — callers use this to decide whether reparse is needed.
    pub fn clear(&self, abs_path: &Path) -> bool {
        self.overlays
            .write()
            .expect("overlay lock poisoned")
            .remove(abs_path)
            .is_some()
    }

    /// Drop every overlay. Not invoked by the LSP today; reserved for future
    /// session-reset paths.
    pub fn clear_all(&self) {
        self.overlays
            .write()
            .expect("overlay lock poisoned")
            .clear();
    }
}

impl Project for OverlayProject {
    fn root(&self) -> &Path {
        self.delegate.root()
    }

    fn analyzer_languages(&self) -> BTreeSet<Language> {
        self.delegate.analyzer_languages()
    }

    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
        self.delegate.all_files()
    }

    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
        self.delegate.analyzable_files(language)
    }

    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
        self.delegate.file_by_rel_path(rel_path)
    }

    fn is_gitignored(&self, rel_path: &Path) -> bool {
        self.delegate.is_gitignored(rel_path)
    }

    fn read_source(&self, file: &ProjectFile) -> io::Result<String> {
        if let Some(text) = self
            .overlays
            .read()
            .expect("overlay lock poisoned")
            .get(&file.abs_path())
        {
            return Ok(text.clone());
        }
        self.delegate.read_source(file)
    }

    fn has_overlay(&self, file: &ProjectFile) -> bool {
        self.overlays
            .read()
            .expect("overlay lock poisoned")
            .contains_key(&file.abs_path())
    }
}

fn detect_languages(root: &Path) -> io::Result<BTreeSet<Language>> {
    let mut languages = BTreeSet::new();
    for file in collect_project_files(root)? {
        if let Some(extension) = file.rel_path().extension().and_then(|ext| ext.to_str()) {
            let language = Language::from_extension(extension);
            if language != Language::None {
                languages.insert(language);
            }
        }
    }
    Ok(languages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_file(root: &Path, rel: &str, contents: &str) -> ProjectFile {
        let abs = root.join(rel);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&abs, contents).unwrap();
        ProjectFile::new(root.to_path_buf(), PathBuf::from(rel))
    }

    #[test]
    fn filesystem_project_read_source_reads_disk() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = write_file(&root, "hello.py", "print('hi')\n");
        let project = FilesystemProject::new(&root).unwrap();
        assert_eq!(project.read_source(&file).unwrap(), "print('hi')\n");
        assert!(!project.has_overlay(&file));
    }

    #[test]
    fn overlay_project_returns_overlay_when_set_and_disk_otherwise() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = write_file(&root, "lib.rs", "fn old() {}\n");
        let delegate: Arc<dyn Project> = Arc::new(FilesystemProject::new(&root).unwrap());
        let overlay = OverlayProject::new(delegate);

        // No overlay yet: falls through to disk.
        assert_eq!(overlay.read_source(&file).unwrap(), "fn old() {}\n");
        assert!(!overlay.has_overlay(&file));

        // Set overlay: served from memory regardless of disk.
        overlay.set(file.abs_path(), "fn new() {}\n".to_string());
        assert_eq!(overlay.read_source(&file).unwrap(), "fn new() {}\n");
        assert!(overlay.has_overlay(&file));

        // Disk is unchanged.
        assert_eq!(
            std::fs::read_to_string(file.abs_path()).unwrap(),
            "fn old() {}\n"
        );

        // Clear: disk reasserts.
        assert!(overlay.clear(&file.abs_path()));
        assert_eq!(overlay.read_source(&file).unwrap(), "fn old() {}\n");
        assert!(!overlay.has_overlay(&file));

        // Clearing a missing overlay returns false.
        assert!(!overlay.clear(&file.abs_path()));
    }

    #[test]
    fn overlay_project_delegates_non_read_methods() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write_file(&root, "a.py", "");
        write_file(&root, "b.py", "");
        let delegate: Arc<dyn Project> = Arc::new(FilesystemProject::new(&root).unwrap());
        let overlay = OverlayProject::new(Arc::clone(&delegate));

        assert_eq!(overlay.root(), delegate.root());
        assert_eq!(overlay.analyzer_languages(), delegate.analyzer_languages());
        assert_eq!(overlay.all_files().unwrap(), delegate.all_files().unwrap());
    }
}
