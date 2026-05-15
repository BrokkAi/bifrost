use crate::analyzer::ProjectFile;

pub(crate) fn normalize_pattern(pattern: &str) -> String {
    pattern.replace('\\', "/")
}

pub(crate) fn rel_path_string(file: &ProjectFile) -> String {
    file.rel_path().to_string_lossy().replace('\\', "/")
}
