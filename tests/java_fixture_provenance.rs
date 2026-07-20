use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

const MISSING: &str = "<missing>";

#[test]
fn checked_in_java_class_fixtures_match_manifest() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/testcode-java");
    verify_class_manifest(&fixture.join("classes.sha256"), &fixture.join("bin"))
        .unwrap_or_else(|message| panic!("Java class fixture provenance mismatch:\n{message}"));
}

#[test]
fn class_manifest_reports_missing_added_and_modified_paths() {
    let temp = tempfile::tempdir().expect("temporary fixture root");
    let classes = temp.path().join("bin");
    fs::create_dir(&classes).expect("class directory");
    fs::write(classes.join("Added.class"), b"added").expect("added class");
    fs::write(classes.join("Modified.class"), b"actual").expect("modified class");

    let manifest = temp.path().join("classes.sha256");
    fs::write(
        &manifest,
        format!(
            "{}  Missing.class\n{}  Modified.class\n",
            "11".repeat(32),
            "22".repeat(32)
        ),
    )
    .expect("fixture manifest");

    let message = verify_class_manifest(&manifest, &classes).expect_err("fixture must differ");
    let added_digest = format!("{:x}", Sha256::digest(b"added"));
    let modified_digest = format!("{:x}", Sha256::digest(b"actual"));
    assert!(message.contains(&format!(
        "Added.class: expected {MISSING}, actual {added_digest}"
    )));
    assert!(message.contains(&format!(
        "Missing.class: expected {}, actual {MISSING}",
        "11".repeat(32)
    )));
    assert!(message.contains(&format!(
        "Modified.class: expected {}, actual {modified_digest}",
        "22".repeat(32)
    )));
}

fn verify_class_manifest(manifest_path: &Path, class_root: &Path) -> Result<(), String> {
    let expected = read_manifest(manifest_path)?;
    let actual = read_class_digests(class_root)?;
    let mut paths: Vec<_> = expected.keys().chain(actual.keys()).cloned().collect();
    paths.sort_unstable();
    paths.dedup();

    let differences: Vec<_> = paths
        .into_iter()
        .filter_map(|path| {
            let expected_digest = expected.get(&path).map(String::as_str).unwrap_or(MISSING);
            let actual_digest = actual.get(&path).map(String::as_str).unwrap_or(MISSING);
            (expected_digest != actual_digest)
                .then(|| format!("{path}: expected {expected_digest}, actual {actual_digest}"))
        })
        .collect();

    if differences.is_empty() {
        Ok(())
    } else {
        Err(differences.join("\n"))
    }
}

fn read_manifest(path: &Path) -> Result<HashMap<String, String>, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let mut entries = HashMap::new();
    for (index, line) in contents.lines().enumerate() {
        let (digest, relative_path) = line.split_once("  ").ok_or_else(|| {
            format!(
                "{}:{} must contain a SHA-256 and relative path separated by two spaces",
                path.display(),
                index + 1
            )
        })?;
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!(
                "{}:{} contains an invalid SHA-256 digest",
                path.display(),
                index + 1
            ));
        }
        if entries
            .insert(relative_path.to_string(), digest.to_ascii_lowercase())
            .is_some()
        {
            return Err(format!(
                "{}:{} repeats path {relative_path}",
                path.display(),
                index + 1
            ));
        }
    }
    Ok(entries)
}

fn read_class_digests(root: &Path) -> Result<HashMap<String, String>, String> {
    let mut entries = HashMap::new();
    for entry in WalkDir::new(root) {
        let entry = entry.map_err(|error| format!("could not walk {}: {error}", root.display()))?;
        if !entry.file_type().is_file() || entry.path().extension().is_none_or(|ext| ext != "class")
        {
            continue;
        }
        let relative_path = stable_relative_path(root, entry.path())?;
        let bytes = fs::read(entry.path())
            .map_err(|error| format!("could not read {}: {error}", entry.path().display()))?;
        entries.insert(relative_path, format!("{:x}", Sha256::digest(bytes)));
    }
    Ok(entries)
}

fn stable_relative_path(root: &Path, path: &Path) -> Result<String, String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|error| format!("{} is outside {}: {error}", path.display(), root.display()))?;
    let components: Result<Vec<_>, _> = relative
        .components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("non-UTF-8 class fixture path: {}", path.display()))
        })
        .collect();
    Ok(components?.join("/"))
}
