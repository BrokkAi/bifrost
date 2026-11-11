//! Offline, fail-closed conversion of pinned legacy rustdoc JSON.
// The analysis and store libraries reach their language tables through
// link-time externs. This target uses analysis but never calls those tables, so
// without this import the linker omits the crate that defines them. MSVC
// resolves the externs before /OPT:REF and fails; GNU ld drops the dead
// sections. Keep the production assembly in the link.
use brokk_bifrost_tools as _;
use flate2::read::GzDecoder;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{env, fs, io::Read, path::Path, process};

mod conversion_contract {
    include!("../../crates/bifrost-rust-analysis/src/analyzer/rust/rustdoc_conversion_contract.rs");
}

const VERSION: &str = "1";
const PRODUCER_CONTRACT: &str = "rustdoc-json-pack-producer/1";
const MAX_BYTES: u64 = 256 * 1024 * 1024;

fn sha256(bytes: &[u8]) -> String {
    brokk_bifrost_analysis::analyzer::canonical_hash::lower_hex_string(
        &Sha256::digest(bytes).into(),
    )
}
fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() > MAX_BYTES {
        return Err("input exceeds 256 MiB".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("input exceeds 256 MiB".into());
    }
    Ok(bytes)
}
fn verify(bytes: &[u8], digest: &str) -> Result<(), String> {
    if sha256(bytes) != digest {
        Err("SHA-256 mismatch".into())
    } else {
        Ok(())
    }
}
fn scan_archive(bytes: &[u8]) -> Result<(), String> {
    let mut archive = tar::Archive::new(GzDecoder::new(bytes));
    let mut count = 0usize;
    let mut entries = 0usize;
    let mut total = 0u64;
    for entry in archive.entries().map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        entries += 1;
        if entries > 100_000 {
            return Err("source archive has too many entries".into());
        }
        total = total
            .checked_add(entry.header().size().map_err(|e| e.to_string())?)
            .ok_or("source archive size overflow")?;
        if total > MAX_BYTES {
            return Err("source archive expands beyond 256 MiB".into());
        }
        let path = entry.path().map_err(|e| e.to_string())?;
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        if !entry.header().entry_type().is_file() {
            return Err("non-file Rust source entry in archive".into());
        }
        count += 1;
        let mut source = Vec::new();
        entry
            .take(MAX_BYTES + 1)
            .read_to_end(&mut source)
            .map_err(|e| e.to_string())?;
        if source.len() as u64 > MAX_BYTES {
            return Err("source file too large".into());
        }
        if source
            .windows(b"staged_api".len())
            .any(|w| w == b"staged_api")
        {
            return Err("staged_api token in source archive".into());
        }
    }
    if count == 0 {
        return Err("source archive contains no Rust files".into());
    }
    Ok(())
}
fn typed_audit(value: &Value, version: u64) -> Result<(), String> {
    let roundtrip = match version {
        54 => serde_json::to_value(
            serde_json::from_value::<rustdoc_types_54::Crate>(value.clone())
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        56 => serde_json::to_value(
            serde_json::from_value::<rustdoc_types_56::Crate>(value.clone())
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        57 => serde_json::to_value(
            serde_json::from_value::<rustdoc_types_57::Crate>(value.clone())
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        _ => return Err(format!("unsupported source format {version}")),
    };
    if &roundtrip != value {
        return Err("source has unknown fields or noncanonical values".into());
    }
    Ok(())
}
fn convert(bytes: &[u8], archive: &[u8]) -> Result<(Vec<u8>, u64, Vec<&'static str>), String> {
    scan_archive(archive)?;
    let mut value: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let version = value
        .get("format_version")
        .and_then(Value::as_u64)
        .ok_or("missing format_version")?;
    typed_audit(&value, version)?;
    let root_id = value
        .get("root")
        .and_then(Value::as_u64)
        .ok_or("missing root")?
        .to_string();
    let index = value
        .get("index")
        .and_then(Value::as_object)
        .ok_or("missing index")?;
    let own_crate = index
        .get(&root_id)
        .and_then(|v| v.get("crate_id"))
        .and_then(Value::as_u64)
        .ok_or("missing root crate_id")?;
    let foreign_index_items = index
        .values()
        .filter(|v| v.get("crate_id").and_then(Value::as_u64) != Some(own_crate))
        .count();
    let external = value
        .get("external_crates")
        .and_then(Value::as_object)
        .ok_or("missing external_crates")?;
    if version < 57 && !external.is_empty() {
        return Err("ExternalCrate::path unavailable in format 54/56".into());
    }
    let paths = value
        .get("paths")
        .and_then(Value::as_object)
        .ok_or("missing paths")?;
    for (id, summary) in paths {
        let crate_id = summary
            .get("crate_id")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("paths[{id}] missing crate_id"))?;
        if crate_id != own_crate && !external.contains_key(&crate_id.to_string()) {
            return Err(format!(
                "paths[{id}] references crate_id {crate_id} without external_crates metadata"
            ));
        }
    }
    let uncertified: Vec<&'static str> = conversion_contract::UNCERTIFIED_FIELD_READS
        .iter()
        .filter(|(_, _, first, last)| *first <= version && version <= *last)
        .map(|(field, _, _, _)| *field)
        .collect();
    value
        .as_object_mut()
        .ok_or("root not object")?
        .insert("format_version".into(), json!(61));
    value.as_object_mut().unwrap().insert("_bifrost_conversion".into(), json!({"converter":"rustdoc-format-converter", "converter_version":VERSION, "producer_contract":PRODUCER_CONTRACT, "uncertified_fields":uncertified, "uncertified_reason":format!("not consumed by producer {PRODUCER_CONTRACT}"), "foreign_index_items":foreign_index_items}));
    // The parser ignores the private certification member. Every typed field must still parse.
    serde_json::from_value::<rustdoc_types::Crate>(value.clone())
        .map_err(|e| format!("format 61 validation: {e}"))?;
    let mut out = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
    out.push(b'\n');
    Ok((out, version, uncertified))
}
fn arg(args: &[String], name: &str) -> Result<String, String> {
    let pos = args
        .iter()
        .position(|v| v == name)
        .ok_or_else(|| format!("missing {name}"))?;
    args.get(pos + 1)
        .cloned()
        .ok_or_else(|| format!("missing value for {name}"))
}
fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let input = arg(&args, "--input")?;
    let source = arg(&args, "--source-archive")?;
    let expected = arg(&args, "--expected-sha256")?;
    let source_expected = arg(&args, "--expected-source-archive-sha256")?;
    let output = arg(&args, "--output")?;
    let manifest = arg(&args, "--manifest")?;
    let bytes = read_bounded(Path::new(&input))?;
    let archive = read_bounded(Path::new(&source))?;
    verify(&bytes, &expected)?;
    verify(&archive, &source_expected)?;
    let (converted, version, uncertified) = convert(&bytes, &archive)?;
    let produced = sha256(&converted);
    let provenance = json!({"original_sha256":expected,"original_format_version":version,"source_archive_sha256":source_expected,"output_sha256":produced,"converter":"rustdoc-format-converter","converter_version":VERSION,"producer_contract":PRODUCER_CONTRACT,"uncertified_fields":uncertified, "uncertified_reason":format!("not consumed by producer {PRODUCER_CONTRACT}")});
    let mut manifest_bytes = serde_json::to_vec(&provenance).map_err(|e| e.to_string())?;
    manifest_bytes.push(b'\n');
    if Path::new(&output).exists() || Path::new(&manifest).exists() {
        if fs::read(&output).ok().as_deref() == Some(converted.as_slice())
            && fs::read(&manifest).ok().as_deref() == Some(manifest_bytes.as_slice())
        {
            println!("source sha256={expected}; output sha256={produced}");
            return Ok(());
        }
        return Err("output or manifest already exists with different bytes".into());
    }
    let out_parent = Path::new(&output)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let manifest_parent = Path::new(&manifest)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temp_out = tempfile::NamedTempFile::new_in(out_parent).map_err(|e| e.to_string())?;
    let mut temp_manifest =
        tempfile::NamedTempFile::new_in(manifest_parent).map_err(|e| e.to_string())?;
    use std::io::Write;
    temp_out.write_all(&converted).map_err(|e| e.to_string())?;
    temp_manifest
        .write_all(&manifest_bytes)
        .map_err(|e| e.to_string())?;
    temp_out
        .persist_noclobber(&output)
        .map_err(|e| e.to_string())?;
    if let Err(error) = temp_manifest.persist_noclobber(&manifest) {
        let message = match fs::remove_file(&output) {
            Ok(()) => format!("manifest persist failed: {error}"),
            Err(cleanup) => {
                format!("manifest persist failed: {error}; output rollback failed: {cleanup}")
            }
        };
        return Err(message);
    }
    println!("source sha256={expected}; output sha256={produced}");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("rustdoc conversion refused: {error}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn archive(source: &str) -> Vec<u8> {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        {
            let mut tar = tar::Builder::new(&mut gz);
            let mut header = tar::Header::new_gnu();
            header.set_size(source.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(
                &mut header,
                "rustdoc-converter-small-0.1.0/src/lib.rs",
                source.as_bytes(),
            )
            .unwrap();
            tar.finish().unwrap();
        }
        gz.finish().unwrap()
    }
    fn native_fixture() -> Value {
        serde_json::from_str(include_str!("../../crates/bifrost-rust-analysis/tests/fixtures/rustdoc-converter-small/native-61.json")).unwrap()
    }
    fn small_archive() -> Vec<u8> {
        archive(include_str!(
            "../../crates/bifrost-rust-analysis/tests/fixtures/rustdoc-converter-small/src/lib.rs"
        ))
    }
    #[test]
    fn symlinked_rust_source_is_refused() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        {
            let mut tar = tar::Builder::new(&mut gz);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o644);
            header.set_link_name("lib.rs").unwrap();
            header.set_cksum();
            tar.append_data(&mut header, "crate/src/module.rs", std::io::empty())
                .unwrap();
            tar.finish().unwrap();
        }
        assert!(
            scan_archive(&gz.finish().unwrap())
                .unwrap_err()
                .contains("non-file Rust source")
        );
    }
    fn strip_new_fields(document: &mut Value) {
        for item in document["index"].as_object_mut().unwrap().values_mut() {
            item.as_object_mut().unwrap().remove("stability");
            item.as_object_mut().unwrap().remove("const_stability");
            if let Some(inner) = item["inner"].as_object_mut() {
                for kind in ["function", "assoc_const", "assoc_type"] {
                    if let Some(body) = inner.get_mut(kind).and_then(Value::as_object_mut) {
                        body.remove("default_unstable");
                    }
                }
            }
        }
    }
    fn fixture(version: u64) -> Vec<u8> {
        let mut old = native_fixture();
        old["format_version"] = json!(version);
        strip_new_fields(&mut old);
        if version < 57 {
            let root = old["root"].as_u64().unwrap().to_string();
            let own_crate = old["index"][&root]["crate_id"].as_u64().unwrap();
            old["paths"]
                .as_object_mut()
                .unwrap()
                .retain(|_, summary| summary["crate_id"].as_u64() == Some(own_crate));
            old["external_crates"] = json!({});
        }
        serde_json::to_vec(&old).unwrap()
    }
    #[test]
    fn source_format_54() {
        let (bytes, v, _) = convert(&fixture(54), &small_archive()).unwrap();
        assert_eq!(v, 54);
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap()["format_version"],
            61
        );
    }
    #[test]
    fn source_54_external_crate_without_path_is_refused() {
        let mut document: Value = serde_json::from_slice(&fixture(54)).unwrap();
        document["external_crates"]["1"] = json!({"name":"std","html_root_url":null});
        assert!(
            convert(
                &serde_json::to_vec(&document).unwrap(),
                &archive("pub use std::fmt;")
            )
            .unwrap_err()
            .contains("ExternalCrate::path")
        );
    }
    #[test]
    fn unknown_source_field_is_refused() {
        let mut document: Value = serde_json::from_slice(&fixture(57)).unwrap();
        document["unknown_new_field"] = json!(1);
        assert!(
            convert(
                &serde_json::to_vec(&document).unwrap(),
                &archive("pub struct A;")
            )
            .unwrap_err()
            .contains("unknown fields")
        );
    }
    #[test]
    fn path_without_external_crate_metadata_is_refused() {
        let mut document: Value = serde_json::from_slice(&fixture(57)).unwrap();
        let local_path = document["paths"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .clone();
        document["paths"]["999999"] = local_path;
        document["paths"]["999999"]["crate_id"] = json!(999999);
        assert!(
            convert(&serde_json::to_vec(&document).unwrap(), &small_archive())
                .unwrap_err()
                .contains("without external_crates metadata")
        );
    }
    #[test]
    fn source_format_56() {
        let (bytes, v, _) = convert(&fixture(56), &small_archive()).unwrap();
        assert_eq!(v, 56);
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap()["format_version"],
            61
        );
    }
    #[test]
    fn source_format_57() {
        let (a, _, _) = convert(&fixture(57), &small_archive()).unwrap();
        let (b, _, _) = convert(&fixture(57), &small_archive()).unwrap();
        assert_eq!(a, b);
        let converted: Value = serde_json::from_slice(&a).unwrap();
        let mut native = native_fixture();
        strip_new_fields(&mut native);
        let mut converted = converted;
        converted
            .as_object_mut()
            .unwrap()
            .remove("_bifrost_conversion");
        assert_eq!(converted, native);
    }
    #[test]
    fn staged_api_is_refused() {
        assert!(
            convert(
                &fixture(57),
                &archive("#![cfg_attr(doc, feature(staged_api))]")
            )
            .unwrap_err()
            .contains("staged_api")
        );
    }
    #[test]
    fn inlined_foreign_item_is_marked_uncertified() {
        let mut foreign: Value = serde_json::from_str(include_str!("../../crates/bifrost-rust-analysis/tests/fixtures/rustdoc-converter-inline/native-61.json")).unwrap();
        foreign["format_version"] = json!(57);
        strip_new_fields(&mut foreign);
        let root = foreign["root"].as_u64().unwrap().to_string();
        foreign["index"]["999999"] = foreign["index"][&root].clone();
        foreign["index"]["999999"]["id"] = json!(999999);
        foreign["index"]["999999"]["crate_id"] = json!(1);
        let (bytes, _, _) = convert(
            &serde_json::to_vec(&foreign).unwrap(),
            &archive(include_str!("../../crates/bifrost-rust-analysis/tests/fixtures/rustdoc-converter-inline/src/lib.rs")),
        )
        .unwrap();
        let converted: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(converted["_bifrost_conversion"]["foreign_index_items"], 1);
        assert!(
            converted["_bifrost_conversion"]["uncertified_fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "Item::stability")
        );
    }
}
