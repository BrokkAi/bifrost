#![allow(dead_code)]

use std::io::{Seek, Write};
use std::path::Path;

use zip::write::SimpleFileOptions;

/// Test archives must not depend on the host. ZIP 9 otherwise records the
/// host creator system in every central-directory entry (`Dos` on Windows,
/// `Unix` elsewhere), which changes the archive bytes and every digest
/// derived from them. Goldens pin those digests, so pin Unix here, where the
/// shared fixture bytes were produced (#13572).
pub fn deterministic_file_options(options: SimpleFileOptions) -> SimpleFileOptions {
    options.system(zip::System::Unix)
}

pub fn write_zip_unwrap<T: AsRef<[u8]>>(
    path: &Path,
    entries: &[(&str, T)],
    options: SimpleFileOptions,
) {
    let file = std::fs::File::create(path).unwrap();
    write_zip_unwrap_to(file, entries, options);
}

pub fn write_zip_unwrap_to<W: Write + Seek, T: AsRef<[u8]>>(
    writer: W,
    entries: &[(&str, T)],
    options: SimpleFileOptions,
) {
    let options = deterministic_file_options(options);
    let mut zip = zip::ZipWriter::new(writer);
    for (entry, contents) in entries {
        zip.start_file(*entry, options).unwrap();
        zip.write_all(contents.as_ref()).unwrap();
    }
    zip.finish().unwrap();
}

pub fn write_stored_source_jar<T: AsRef<[u8]>>(path: &Path, entries: &[(&str, T)]) {
    let file = std::fs::File::create(path).expect("create source jar");
    let mut zip = zip::ZipWriter::new(file);
    for (entry, contents) in entries {
        zip.start_file(
            *entry,
            deterministic_file_options(
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
            ),
        )
        .expect("start jar entry");
        zip.write_all(contents.as_ref()).expect("write jar entry");
    }
    zip.finish().expect("finish source jar");
}
