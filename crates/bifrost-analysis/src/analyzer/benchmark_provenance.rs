//! Shared, framed Git provenance for ignored analyzer benchmarks.

use std::fs;
use std::path::Path;
use std::process::Command;

use sha2::{Digest, Sha256};

pub(crate) fn git_tree_fingerprint(root: &Path, excluded_paths: &[&Path]) -> Option<String> {
    let commit = command_output_in(root, "git", &["rev-parse", "HEAD"])?;
    let excluded = excluded_paths
        .iter()
        .filter_map(|path| path.strip_prefix(root).ok())
        .map(|path| path.to_string_lossy().replace('\\', "/"))
        .collect::<Vec<_>>();

    let mut diff = Command::new("git");
    diff.current_dir(root)
        .args(["diff", "--binary", "HEAD", "--", "."]);
    for relative in &excluded {
        diff.arg(format!(":(exclude){relative}"));
    }
    let diff = diff
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    let untracked = Command::new("git")
        .current_dir(root)
        .args(["ls-files", "--others", "--exclude-standard", "-z"])
        .output()
        .ok()
        .filter(|output| output.status.success())?;

    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b'c', commit.as_bytes())?;
    hash_field(&mut hasher, b'd', &diff.stdout)?;
    for raw_path in untracked.stdout.split(|byte| *byte == 0) {
        if raw_path.is_empty() {
            continue;
        }
        let relative = std::str::from_utf8(raw_path).ok()?;
        if excluded.iter().any(|excluded| excluded == relative) {
            continue;
        }
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path).ok()?;
        hash_field(&mut hasher, b'p', raw_path)?;
        if metadata.is_dir() {
            hash_field(&mut hasher, b't', b"directory")?;
            continue;
        }
        hash_field(&mut hasher, b'f', &fs::read(path).ok()?)?;
    }
    Some(hex_digest(hasher.finalize()))
}

pub(crate) fn command_output_in(root: &Path, program: &str, arguments: &[&str]) -> Option<String> {
    Command::new(program)
        .current_dir(root)
        .args(arguments)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_owned())
}

fn hash_field(hasher: &mut Sha256, tag: u8, bytes: &[u8]) -> Option<()> {
    hasher.update([tag]);
    hasher.update(u64::try_from(bytes.len()).ok()?.to_le_bytes());
    hasher.update(bytes);
    Some(())
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    use std::fmt::Write as _;

    bytes
        .as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").expect("write to String");
            output
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_framing_distinguishes_path_content_boundaries() {
        fn digest(fields: &[(u8, &[u8])]) -> String {
            let mut hasher = Sha256::new();
            for &(tag, bytes) in fields {
                hash_field(&mut hasher, tag, bytes).unwrap();
            }
            hex_digest(hasher.finalize())
        }

        assert_ne!(
            digest(&[(b'p', b"a"), (b'f', b"bc")]),
            digest(&[(b'p', b"ab"), (b'f', b"c")])
        );
    }
}
