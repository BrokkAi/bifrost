/// Whether `path` starts with a Windows drive, rooted, UNC, or device prefix.
///
/// `std::path` interprets prefixes for the host platform, so Unix would
/// otherwise accept spellings such as `C:query.rql` as ordinary relative file
/// names. Workspace paths are a portable wire contract and reject those
/// prefixes consistently on every host.
pub fn has_portable_windows_path_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
        || bytes.first() == Some(&b'\\')
}
