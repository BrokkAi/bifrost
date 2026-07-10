use std::path::PathBuf;

/// Lexically normalize a path while preserving its absolute/relative form.
///
/// On Windows, ordinary and verbatim disk/UNC prefixes collapse to the same
/// spelling so canonicalized roots and user-provided roots share one identity.
pub(crate) trait NormalizePath {
    fn normalize(self) -> PathBuf;
}

impl NormalizePath for PathBuf {
    fn normalize(self) -> PathBuf {
        let mut normalized = PathBuf::new();
        for component in self.components() {
            match component {
                #[cfg(windows)]
                std::path::Component::Prefix(prefix) => {
                    push_normalized_windows_prefix(&mut normalized, prefix);
                }
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    normalized.pop();
                }
                component => normalized.push(component.as_os_str()),
            }
        }
        normalized
    }
}

#[cfg(windows)]
fn push_normalized_windows_prefix(
    normalized: &mut PathBuf,
    prefix: std::path::PrefixComponent<'_>,
) {
    use std::path::Prefix;

    match prefix.kind() {
        Prefix::VerbatimDisk(drive) | Prefix::Disk(drive) => {
            normalized.push(format!("{}:", drive as char));
        }
        Prefix::VerbatimUNC(server, share) | Prefix::UNC(server, share) => {
            normalized.push(format!(
                r"\\{}\{}",
                server.to_string_lossy(),
                share.to_string_lossy()
            ));
        }
        Prefix::Verbatim(_) | Prefix::DeviceNS(_) => {
            normalized.push(prefix.as_os_str());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn removes_current_and_parent_components() {
        let path = PathBuf::from("src")
            .join(".")
            .join("nested")
            .join("..")
            .join("lib.rs");
        assert_eq!(path.normalize(), Path::new("src/lib.rs"));
    }

    #[cfg(windows)]
    #[test]
    fn normalizes_verbatim_and_ordinary_disk_roots_equally() {
        let ordinary = PathBuf::from(r"C:\Users\runner\repo").normalize();
        let verbatim = PathBuf::from(r"\\?\C:\Users\runner\repo").normalize();
        assert_eq!(ordinary, verbatim);
    }

    #[cfg(windows)]
    #[test]
    fn normalizes_verbatim_and_ordinary_unc_roots_equally() {
        let ordinary = PathBuf::from(r"\\server\share\repo").normalize();
        let verbatim = PathBuf::from(r"\\?\UNC\server\share\repo").normalize();
        assert_eq!(ordinary, verbatim);
    }
}
