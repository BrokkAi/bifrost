#![allow(dead_code)]

use std::io::{Seek, Write};
use std::path::Path;

use zip::write::SimpleFileOptions;

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
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )
        .expect("start jar entry");
        zip.write_all(contents.as_ref()).expect("write jar entry");
    }
    zip.finish().expect("finish source jar");
}
