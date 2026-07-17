use super::dependency_discovery::project_assets_files;
use crate::analyzer::{CSharpAnalyzerConfig, Project};
use crate::hash::HashMap;
use goblin::pe::PE;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const MAX_ASSEMBLY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ASSETS_BYTES: u64 = 8 * 1024 * 1024;
const MAX_METADATA_ROWS: u32 = 100_000;
const MAX_METADATA_TOTAL_ROWS: u32 = 250_000;
const MAX_SIGNATURE_DEPTH: usize = 64;
const MAX_PROJECT_OUTPUTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CSharpExternalTypeKind {
    Class,
    Interface,
    Struct,
    Enum,
    Delegate,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CSharpVisibility {
    Private,
    Internal,
    ProtectedAndInternal,
    Protected,
    ProtectedOrInternal,
    Public,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CSharpExternalMemberKind {
    Constructor,
    Method,
    Field,
    Property,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CSharpExternalDeclarationSource {
    Assembly { path: PathBuf, metadata_token: u32 },
}

#[derive(Debug, Clone)]
pub struct CSharpExternalMember {
    owner_fqn: String,
    name: String,
    kind: CSharpExternalMemberKind,
    visibility: CSharpVisibility,
    is_static: bool,
    is_abstract: bool,
    is_virtual: bool,
    generic_arity: usize,
    return_type: Option<String>,
    parameter_types: Vec<String>,
    source: CSharpExternalDeclarationSource,
}
impl CSharpExternalMember {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn kind(&self) -> CSharpExternalMemberKind {
        self.kind
    }
    pub fn owner_fqn(&self) -> &str {
        &self.owner_fqn
    }
    pub fn return_type(&self) -> Option<&str> {
        self.return_type.as_deref()
    }
    pub fn parameter_types(&self) -> &[String] {
        &self.parameter_types
    }
    pub fn visibility(&self) -> CSharpVisibility {
        self.visibility
    }
    pub fn is_static(&self) -> bool {
        self.is_static
    }
    pub fn is_abstract(&self) -> bool {
        self.is_abstract
    }
    pub fn is_virtual(&self) -> bool {
        self.is_virtual
    }
    pub fn generic_arity(&self) -> usize {
        self.generic_arity
    }
    pub fn source(&self) -> &CSharpExternalDeclarationSource {
        &self.source
    }
    fn externally_visible(&self) -> bool {
        matches!(
            self.visibility,
            CSharpVisibility::Public
                | CSharpVisibility::Protected
                | CSharpVisibility::ProtectedOrInternal
        )
    }
}

#[derive(Debug, Clone)]
pub struct CSharpExternalType {
    fqn: String,
    namespace: String,
    short_name: String,
    kind: CSharpExternalTypeKind,
    visibility: CSharpVisibility,
    generic_arity: usize,
    interfaces: Vec<String>,
    source: CSharpExternalDeclarationSource,
    members: Vec<CSharpExternalMember>,
    is_effectively_visible: bool,
}
impl CSharpExternalType {
    pub fn fqn(&self) -> &str {
        &self.fqn
    }
    pub fn members(&self) -> &[CSharpExternalMember] {
        &self.members
    }
    pub fn kind(&self) -> CSharpExternalTypeKind {
        self.kind
    }
    pub fn visibility(&self) -> CSharpVisibility {
        self.visibility
    }
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    pub fn short_name(&self) -> &str {
        &self.short_name
    }
    pub fn generic_arity(&self) -> usize {
        self.generic_arity
    }
    pub fn interfaces(&self) -> &[String] {
        &self.interfaces
    }
    pub fn source(&self) -> &CSharpExternalDeclarationSource {
        &self.source
    }
    fn externally_visible(&self) -> bool {
        self.is_effectively_visible
    }
}

#[derive(Debug, Clone, Default)]
pub struct CSharpExternalDeclarationIndex {
    types: HashMap<String, Vec<CSharpExternalType>>,
}
impl CSharpExternalDeclarationIndex {
    pub fn build_for_project(config: &CSharpAnalyzerConfig, project: &dyn Project) -> Self {
        let mut paths = config.assembly_paths.clone();
        for assets in project_assets_files(project.root()) {
            paths.extend(assemblies_from_assets(&assets));
        }
        paths.sort();
        paths.dedup();
        let mut index = Self::default();
        for path in paths {
            index.index_assembly(&path);
        }
        index
    }
    pub fn resolve_in_file(
        &self,
        reference: &str,
        namespace: &str,
        usings: &[String],
        aliases: &HashMap<String, String>,
    ) -> Vec<&CSharpExternalType> {
        let mut name = reference.trim().trim_end_matches('?').to_string();
        if let Some((alias, suffix)) = name.split_once("::") {
            name = if alias == "global" {
                suffix.to_string()
            } else {
                aliases
                    .get(alias)
                    .map(|p| {
                        if suffix.is_empty() {
                            p.clone()
                        } else {
                            format!("{p}.{suffix}")
                        }
                    })
                    .unwrap_or(name)
            };
        }
        name = metadata_type_identity(&name);
        let mut keys = Vec::new();
        if name.contains('.') {
            keys.push(name);
        } else {
            if !namespace.is_empty() {
                keys.push(format!("{namespace}.{name}"));
            }
            keys.extend(usings.iter().map(|u| format!("{u}.{name}")));
            keys.push(name);
        }
        keys.into_iter()
            .flat_map(|key| self.types.get(&key).into_iter().flatten())
            .filter(|ty| ty.externally_visible())
            .collect()
    }
    pub fn members_named(&self, owner: &str, name: &str) -> Vec<&CSharpExternalMember> {
        self.types
            .get(owner)
            .into_iter()
            .flatten()
            .filter(|ty| ty.externally_visible())
            .flat_map(|ty| ty.members.iter())
            .filter(|m| m.externally_visible())
            .filter(|m| m.name == name)
            .collect()
    }
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }
    fn index_assembly(&mut self, path: &Path) {
        let Ok(meta) = fs::metadata(path) else { return };
        if !meta.is_file() || meta.len() > MAX_ASSEMBLY_BYTES {
            return;
        };
        let Ok(bytes) = fs::read(path) else { return };
        let Some(types) = parse_assembly(path, &bytes) else {
            return;
        };
        for ty in types {
            self.types.entry(ty.fqn.clone()).or_default().push(ty);
        }
    }
}

fn metadata_type_identity(reference: &str) -> String {
    let reference = reference.trim().trim_end_matches("[]");
    let Some(open) = reference.find('<') else {
        return reference.to_string();
    };
    let Some(close) = reference.rfind('>') else {
        return reference[..open].trim().to_string();
    };
    if close < open {
        return reference[..open].trim().to_string();
    }
    let mut depth = 0usize;
    let mut arity = 1usize;
    for character in reference[open + 1..close].chars() {
        match character {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => arity += 1,
            _ => {}
        }
    }
    format!("{}`{arity}", reference[..open].trim())
}

fn assemblies_from_assets(path: &Path) -> Vec<PathBuf> {
    let Ok(meta) = fs::metadata(path) else {
        return Vec::new();
    };
    if meta.len() > MAX_ASSETS_BYTES {
        return Vec::new();
    };
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(root): Result<Value, _> = serde_json::from_str(&text) else {
        return Vec::new();
    };
    let workspace_root = path
        .parent()
        .and_then(Path::parent)
        .and_then(|root| root.canonicalize().ok());
    let approved_package_roots = approved_package_roots(workspace_root.as_deref());
    let folders = root
        .get("packageFolders")
        .and_then(Value::as_object)
        .map(|o| {
            o.keys()
                .filter_map(|folder| PathBuf::from(folder).canonicalize().ok())
                .filter(|folder| approved_package_roots.contains(folder))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut out = Vec::new();
    for target in root
        .get("targets")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|o| o.values())
        .filter_map(Value::as_object)
    {
        for (library, entry) in target {
            for section in ["compile", "ref", "runtime"] {
                for relative in entry
                    .get(section)
                    .and_then(Value::as_object)
                    .into_iter()
                    .flat_map(|o| o.keys())
                {
                    if !relative.ends_with(".dll") && !relative.ends_with(".exe") {
                        continue;
                    }
                    let Some(relative) = safe_relative_path(relative) else {
                        continue;
                    };
                    let Some(library) = safe_relative_path(library) else {
                        continue;
                    };
                    for folder in &folders {
                        let candidate = folder.join(library).join(relative);
                        if let Ok(candidate) = candidate.canonicalize()
                            && candidate.starts_with(&folder)
                            && candidate.is_file()
                        {
                            out.push(candidate);
                        }
                    }
                    if let (Some(root), Some(project_path)) = (
                        workspace_root.as_ref(),
                        root.get("libraries")
                            .and_then(Value::as_object)
                            .and_then(|libraries| libraries.get(library.to_string_lossy().as_ref()))
                            .filter(|entry| {
                                entry.get("type").and_then(Value::as_str) == Some("project")
                            })
                            .and_then(|entry| entry.get("path"))
                            .and_then(Value::as_str),
                    ) {
                        let project_path = path
                            .parent()
                            .and_then(Path::parent)
                            .unwrap_or(root)
                            .join(project_path);
                        if let Ok(project_path) = project_path.canonicalize()
                            && project_path.starts_with(root)
                        {
                            let project_root = if project_path.is_dir() {
                                project_path
                            } else {
                                project_path
                                    .parent()
                                    .map(Path::to_path_buf)
                                    .unwrap_or_default()
                            };
                            out.extend(project_output_candidates(
                                &project_root,
                                relative.file_name(),
                                root,
                            ));
                        }
                    }
                }
            }
        }
    }
    out
}

fn approved_package_roots(workspace_root: Option<&Path>) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(path) = std::env::var_os("NUGET_PACKAGES").map(PathBuf::from) {
        roots.push(path);
    }
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        roots.push(home.join(".nuget/packages"));
    }
    if let Some(root) = workspace_root {
        roots.push(root.join(".nuget/packages"));
    }
    roots
        .into_iter()
        .filter_map(|root| root.canonicalize().ok())
        .collect()
}

fn project_output_candidates(
    project_root: &Path,
    filename: Option<&std::ffi::OsStr>,
    workspace_root: &Path,
) -> Vec<PathBuf> {
    let Some(filename) = filename else {
        return Vec::new();
    };
    let bin = project_root.join("bin");
    if !bin.is_dir() {
        return Vec::new();
    }
    WalkDir::new(bin)
        .follow_links(false)
        .max_depth(5)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file() && entry.file_name() == filename)
        .filter_map(|entry| entry.into_path().canonicalize().ok())
        .filter(|candidate| candidate.starts_with(workspace_root))
        .take(MAX_PROJECT_OUTPUTS)
        .collect()
}

fn safe_relative_path(value: &str) -> Option<&Path> {
    let path = Path::new(value);
    (!path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_))))
    .then_some(path)
}

#[derive(Clone)]
struct TypeRow {
    flags: u32,
    name: String,
    namespace: String,
    extends: u32,
    field_start: u32,
    method_start: u32,
}
#[derive(Clone)]
struct TypeRefRow {
    scope: u32,
    name: String,
    namespace: String,
}
#[derive(Clone)]
struct TypeSpecRow {
    sig: Vec<u8>,
}
#[derive(Clone)]
struct FieldRow {
    flags: u16,
    name: String,
    sig: Vec<u8>,
}
#[derive(Clone)]
struct MethodRow {
    flags: u16,
    name: String,
    sig: Vec<u8>,
}
#[derive(Clone)]
struct PropertyRow {
    flags: u16,
    name: String,
    sig: Vec<u8>,
}

fn parse_assembly(path: &Path, bytes: &[u8]) -> Option<Vec<CSharpExternalType>> {
    let pe = PE::parse(bytes).ok()?;
    let metadata = metadata_bytes(&pe, bytes)?;
    let streams = Streams::parse(metadata)?;
    let tables = streams.tables?;
    let strings = streams.strings.unwrap_or(&[]);
    let blobs = streams.blobs.unwrap_or(&[]);
    let layout = TableLayout::parse(tables)?;
    if layout.rows.iter().any(|rows| *rows > MAX_METADATA_ROWS)
        || layout
            .rows
            .iter()
            .try_fold(0u32, |total, rows| total.checked_add(*rows))?
            > MAX_METADATA_TOTAL_ROWS
        || strings.len() > MAX_ASSETS_BYTES as usize
        || blobs.len() > MAX_ASSETS_BYTES as usize
    {
        return None;
    }
    let types = (1..=layout.rows(2))
        .map(|i| read_typedef(&layout, i, strings))
        .collect::<Option<Vec<_>>>()?;
    let type_refs = (1..=layout.rows(1))
        .map(|i| read_typeref(&layout, i, strings))
        .collect::<Option<Vec<_>>>()?;
    let type_specs = (1..=layout.rows(27))
        .map(|i| read_typespec(&layout, i, blobs))
        .collect::<Option<Vec<_>>>()?;
    let fields = (1..=layout.rows(4))
        .map(|i| read_field(&layout, i, strings, blobs))
        .collect::<Option<Vec<_>>>()?;
    let methods = (1..=layout.rows(6))
        .map(|i| read_method(&layout, i, strings, blobs))
        .collect::<Option<Vec<_>>>()?;
    let properties = (1..=layout.rows(23))
        .map(|i| read_property(&layout, i, strings, blobs))
        .collect::<Option<Vec<_>>>()?;
    let nested = nested_map(&layout);
    let property_owners = property_owners(&layout, types.len() as u32, properties.len() as u32);
    let property_accessors = property_accessors(&layout, &methods);
    let generic = generic_arities(&layout, types.len() as u32);
    let interfaces = interfaces_for(&layout, &types, &type_refs, &type_specs);
    let mut names = Vec::new();
    for (idx, row) in types.iter().enumerate() {
        names.push(full_type_name((idx + 1) as u32, row, &types, &nested));
    }
    let mut result = Vec::new();
    for (idx, row) in types.iter().enumerate() {
        let token = 0x0200_0000 | ((idx + 1) as u32);
        let fqn = names[idx].clone();
        let end_field = types
            .get(idx + 1)
            .map(|r| r.field_start)
            .unwrap_or(fields.len() as u32 + 1);
        let end_method = types
            .get(idx + 1)
            .map(|r| r.method_start)
            .unwrap_or(methods.len() as u32 + 1);
        let mut members = Vec::new();
        for (field_index, f) in fields
            .iter()
            .enumerate()
            .skip(row.field_start.saturating_sub(1) as usize)
            .take(end_field.saturating_sub(row.field_start) as usize)
        {
            members.push(member(
                path,
                0x0400_0000 | (field_index as u32 + 1),
                &fqn,
                &f.name,
                CSharpExternalMemberKind::Field,
                f.flags,
                false,
                &f.sig,
                &types,
                &type_refs,
                &type_specs,
            ));
        }
        for (method_index, m) in methods
            .iter()
            .enumerate()
            .skip(row.method_start.saturating_sub(1) as usize)
            .take(end_method.saturating_sub(row.method_start) as usize)
        {
            let kind = if m.name == ".ctor" || m.name == ".cctor" {
                CSharpExternalMemberKind::Constructor
            } else {
                CSharpExternalMemberKind::Method
            };
            members.push(member(
                path,
                0x0600_0000 | (method_index as u32 + 1),
                &fqn,
                &m.name,
                kind,
                m.flags,
                true,
                &m.sig,
                &types,
                &type_refs,
                &type_specs,
            ));
        }
        for (pidx, p) in properties
            .iter()
            .enumerate()
            .filter(|(pidx, _)| property_owners.get(&(*pidx as u32 + 1)) == Some(&(idx as u32 + 1)))
        {
            let flags = property_accessors
                .get(&(pidx as u32 + 1))
                .copied()
                .unwrap_or(p.flags);
            members.push(member(
                path,
                0x1700_0000 | (pidx as u32 + 1),
                &fqn,
                &p.name,
                CSharpExternalMemberKind::Property,
                flags,
                false,
                &p.sig,
                &types,
                &type_refs,
                &type_specs,
            ));
        }
        let namespace = fqn
            .rsplit_once('.')
            .map(|(ns, _)| ns.to_string())
            .unwrap_or_default();
        let short_name = fqn.rsplit('.').next().unwrap_or(&fqn).to_string();
        let base = resolve_typedef_or_ref(row.extends, &types, &type_refs, &type_specs);
        let kind = if row.flags & 0x20 != 0 {
            CSharpExternalTypeKind::Interface
        } else if base.ends_with("System.Enum") {
            CSharpExternalTypeKind::Enum
        } else if base.ends_with("System.ValueType") {
            CSharpExternalTypeKind::Struct
        } else if base.ends_with("System.MulticastDelegate") {
            CSharpExternalTypeKind::Delegate
        } else {
            CSharpExternalTypeKind::Class
        };
        result.push(CSharpExternalType {
            fqn,
            namespace,
            short_name,
            kind,
            visibility: type_visibility(row.flags),
            generic_arity: *generic.get(&((idx + 1) as u32)).unwrap_or(&0),
            interfaces: interfaces
                .get(&((idx + 1) as u32))
                .cloned()
                .unwrap_or_default(),
            source: CSharpExternalDeclarationSource::Assembly {
                path: path.to_path_buf(),
                metadata_token: token,
            },
            members,
            is_effectively_visible: false,
        });
    }
    for index in 0..result.len() {
        result[index].is_effectively_visible =
            effective_type_visibility((index + 1) as u32, &result, &nested);
    }
    Some(result)
}

fn effective_type_visibility(
    mut index: u32,
    types: &[CSharpExternalType],
    nested: &HashMap<u32, u32>,
) -> bool {
    for _ in 0..types.len() {
        let Some(ty) = types.get(index.saturating_sub(1) as usize) else {
            return false;
        };
        if !matches!(
            ty.visibility,
            CSharpVisibility::Public
                | CSharpVisibility::Protected
                | CSharpVisibility::ProtectedOrInternal
        ) {
            return false;
        }
        let Some(owner) = nested.get(&index).copied() else {
            return true;
        };
        index = owner;
    }
    false
}

fn metadata_bytes<'a>(pe: &PE<'_>, bytes: &'a [u8]) -> Option<&'a [u8]> {
    let clr = pe.clr_data?;
    let rva = clr.cor20_header.metadata.virtual_address;
    let size = clr.cor20_header.metadata.size as usize;
    let section = pe.sections.iter().find(|section| {
        rva >= section.virtual_address
            && rva
                < section
                    .virtual_address
                    .saturating_add(section.virtual_size.max(1))
    })?;
    let offset =
        section.pointer_to_raw_data as usize + rva.checked_sub(section.virtual_address)? as usize;
    bytes.get(offset..offset.checked_add(size)?)
}

fn member(
    path: &Path,
    token: u32,
    owner: &str,
    name: &str,
    kind: CSharpExternalMemberKind,
    flags: u16,
    method: bool,
    sig: &[u8],
    types: &[TypeRow],
    type_refs: &[TypeRefRow],
    type_specs: &[TypeSpecRow],
) -> CSharpExternalMember {
    let (ret, params, generic) = decode_signature(sig, method, types, type_refs, type_specs);
    CSharpExternalMember {
        owner_fqn: owner.to_string(),
        name: name.to_string(),
        kind,
        visibility: member_visibility(flags),
        is_static: flags & 0x10 != 0,
        is_abstract: flags & 0x400 != 0,
        is_virtual: flags & 0x40 != 0,
        generic_arity: generic,
        return_type: ret,
        parameter_types: params,
        source: CSharpExternalDeclarationSource::Assembly {
            path: path.to_path_buf(),
            metadata_token: token,
        },
    }
}

struct Streams<'a> {
    tables: Option<&'a [u8]>,
    strings: Option<&'a [u8]>,
    blobs: Option<&'a [u8]>,
}
impl<'a> Streams<'a> {
    fn parse(bytes: &'a [u8]) -> Option<Self> {
        let mut p = 0;
        take(bytes, &mut p, 4)?;
        take(bytes, &mut p, 2)?;
        take(bytes, &mut p, 2)?;
        take(bytes, &mut p, 4)?;
        let len = u32at(bytes, &mut p)? as usize;
        take(bytes, &mut p, len)?;
        p = (p + 3) & !3;
        take(bytes, &mut p, 2)?;
        let count = u16at(bytes, &mut p)?;
        let mut out = Self {
            tables: None,
            strings: None,
            blobs: None,
        };
        for _ in 0..count {
            let off = u32at(bytes, &mut p)? as usize;
            let size = u32at(bytes, &mut p)? as usize;
            let start = p;
            while *bytes.get(p)? != 0 {
                p += 1;
            }
            let name = std::str::from_utf8(&bytes[start..p]).ok()?;
            p = (p + 4) & !3;
            let Some(end) = off.checked_add(size) else {
                continue;
            };
            let Some(data) = bytes.get(off..end) else {
                continue;
            };
            match name {
                "#~" | "#-" => out.tables = Some(data),
                "#Strings" => out.strings = Some(data),
                "#Blob" => out.blobs = Some(data),
                _ => {}
            }
        }
        Some(out)
    }
}
struct TableLayout<'a> {
    data: &'a [u8],
    rows: [u32; 45],
    starts: [usize; 45],
    heap: u8,
}
impl<'a> TableLayout<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
        let mut p = 0;
        take(data, &mut p, 4)?;
        take(data, &mut p, 1)?;
        take(data, &mut p, 1)?;
        let heap = *take(data, &mut p, 1)?.first()?;
        take(data, &mut p, 1)?;
        let valid = u64at(data, &mut p)?;
        take(data, &mut p, 8)?;
        let mut rows = [0; 45];
        for i in 0..45 {
            if valid & (1 << i) != 0 {
                rows[i] = u32at(data, &mut p)?;
            }
        }
        let mut starts = [0; 45];
        for i in 0..45 {
            if rows[i] > 0 {
                starts[i] = p;
                p = p.checked_add(rows[i] as usize * row_size(i, &rows, heap)?)?;
                if p > data.len() {
                    return None;
                }
            }
        }
        Some(Self {
            data,
            rows,
            starts,
            heap,
        })
    }
    fn rows(&self, n: usize) -> u32 {
        self.rows[n]
    }
    fn row(&self, t: usize, index: u32) -> Option<&[u8]> {
        let size = row_size(t, &self.rows, self.heap)?;
        let start = self.starts[t].checked_add(index.checked_sub(1)? as usize * size)?;
        self.data.get(start..start + size)
    }
}
fn read_typedef(l: &TableLayout<'_>, i: u32, s: &[u8]) -> Option<TypeRow> {
    let mut p = 0;
    let r = l.row(2, i)?;
    let flags = u32at(r, &mut p)?;
    let name = str_index(r, &mut p, l.heap, s)?;
    let namespace = str_index(r, &mut p, l.heap, s)?;
    let extends = index(r, &mut p, coded_size(&l.rows, &[2, 1, 27], 2))?;
    let field_start = index(r, &mut p, index_size(l.rows(4)))?;
    let method_start = index(r, &mut p, index_size(l.rows(6)))?;
    Some(TypeRow {
        flags,
        name,
        namespace,
        extends,
        field_start,
        method_start,
    })
}
fn read_typeref(l: &TableLayout<'_>, i: u32, s: &[u8]) -> Option<TypeRefRow> {
    let mut p = 0;
    let r = l.row(1, i)?;
    let scope = index(r, &mut p, coded_size(&l.rows, &[0, 26, 35, 1], 2))?;
    let name = str_index(r, &mut p, l.heap, s)?;
    let namespace = str_index(r, &mut p, l.heap, s)?;
    Some(TypeRefRow {
        scope,
        name,
        namespace,
    })
}
fn read_typespec(l: &TableLayout<'_>, i: u32, blobs: &[u8]) -> Option<TypeSpecRow> {
    let mut p = 0;
    let sig = blob_index(l.row(27, i)?, &mut p, l.heap, blobs)?;
    Some(TypeSpecRow { sig })
}
fn read_field(l: &TableLayout<'_>, i: u32, s: &[u8], b: &[u8]) -> Option<FieldRow> {
    let mut p = 0;
    let r = l.row(4, i)?;
    let flags = u16at(r, &mut p)?;
    let name = str_index(r, &mut p, l.heap, s)?;
    let sig = blob_index(r, &mut p, l.heap, b)?;
    Some(FieldRow { flags, name, sig })
}
fn read_method(l: &TableLayout<'_>, i: u32, s: &[u8], b: &[u8]) -> Option<MethodRow> {
    let mut p = 0;
    let r = l.row(6, i)?;
    take(r, &mut p, 4)?;
    take(r, &mut p, 2)?;
    let flags = u16at(r, &mut p)?;
    let name = str_index(r, &mut p, l.heap, s)?;
    let sig = blob_index(r, &mut p, l.heap, b)?;
    Some(MethodRow { flags, name, sig })
}
fn read_property(l: &TableLayout<'_>, i: u32, s: &[u8], b: &[u8]) -> Option<PropertyRow> {
    let mut p = 0;
    let r = l.row(23, i)?;
    let flags = u16at(r, &mut p)?;
    let name = str_index(r, &mut p, l.heap, s)?;
    let sig = blob_index(r, &mut p, l.heap, b)?;
    Some(PropertyRow { flags, name, sig })
}

fn nested_map(l: &TableLayout<'_>) -> HashMap<u32, u32> {
    let mut out = HashMap::default();
    for i in 1..=l.rows(41) {
        let Some(r) = l.row(41, i) else { continue };
        let mut p = 0;
        let Some(nested) = index(r, &mut p, index_size(l.rows(2))) else {
            continue;
        };
        let Some(owner) = index(r, &mut p, index_size(l.rows(2))) else {
            continue;
        };
        out.insert(nested, owner);
    }
    out
}
fn property_owners(l: &TableLayout<'_>, type_count: u32, prop_count: u32) -> HashMap<u32, u32> {
    let mut maps = Vec::new();
    for i in 1..=l.rows(21) {
        let Some(r) = l.row(21, i) else { continue };
        let mut p = 0;
        let Some(owner) = index(r, &mut p, index_size(type_count)) else {
            continue;
        };
        let Some(start) = index(r, &mut p, index_size(prop_count)) else {
            continue;
        };
        if owner > 0 && owner <= type_count && start > 0 && start <= prop_count.saturating_add(1) {
            maps.push((owner, start));
        }
    }
    maps.sort();
    let mut out = HashMap::default();
    for (idx, (owner, start)) in maps.iter().enumerate() {
        let end = maps
            .get(idx + 1)
            .map(|(_, start)| *start)
            .unwrap_or(prop_count + 1);
        if end < *start || end > prop_count.saturating_add(1) {
            continue;
        }
        for p in *start..end {
            out.insert(p, *owner);
        }
    }
    out
}
fn property_accessors(l: &TableLayout<'_>, methods: &[MethodRow]) -> HashMap<u32, u16> {
    let mut out = HashMap::default();
    for i in 1..=l.rows(24) {
        let Some(row) = l.row(24, i) else {
            continue;
        };
        let mut p = 0;
        let Some(_) = u16at(row, &mut p) else {
            continue;
        };
        let Some(method) = index(row, &mut p, index_size(methods.len() as u32)) else {
            continue;
        };
        let Some(association) = index(row, &mut p, coded_size(&l.rows, &[20, 23], 1)) else {
            continue;
        };
        if association & 1 != 1 {
            continue;
        }
        let Some(method) = methods.get(method.saturating_sub(1) as usize) else {
            continue;
        };
        let property = association >> 1;
        out.entry(property)
            .and_modify(|flags| {
                if method.flags & 7 > *flags & 7 {
                    *flags = method.flags;
                }
            })
            .or_insert(method.flags);
    }
    out
}
fn generic_arities(l: &TableLayout<'_>, type_count: u32) -> HashMap<u32, usize> {
    let mut out = HashMap::default();
    for i in 1..=l.rows(42) {
        let Some(r) = l.row(42, i) else { continue };
        let mut p = 0;
        let _ = u16at(r, &mut p);
        let _ = u16at(r, &mut p);
        let Some(owner) = index(r, &mut p, coded_size(&l.rows, &[2, 6], 1)) else {
            continue;
        };
        if owner & 1 == 0 {
            let ty = owner >> 1;
            if ty > 0 && ty <= type_count {
                *out.entry(ty).or_insert(0) += 1;
            }
        }
    }
    out
}
fn interfaces_for(
    l: &TableLayout<'_>,
    types: &[TypeRow],
    type_refs: &[TypeRefRow],
    type_specs: &[TypeSpecRow],
) -> HashMap<u32, Vec<String>> {
    let mut out = HashMap::default();
    for i in 1..=l.rows(9) {
        let Some(r) = l.row(9, i) else { continue };
        let mut p = 0;
        let Some(owner) = index(r, &mut p, index_size(types.len() as u32)) else {
            continue;
        };
        let Some(interface) = index(r, &mut p, coded_size(&l.rows, &[2, 1, 27], 2)) else {
            continue;
        };
        let value = resolve_typedef_or_ref(interface, types, type_refs, type_specs);
        if !value.is_empty() {
            out.entry(owner).or_insert_with(Vec::new).push(value);
        }
    }
    out
}
fn full_type_name(
    index: u32,
    row: &TypeRow,
    all: &[TypeRow],
    nested: &HashMap<u32, u32>,
) -> String {
    let mut parts = vec![row.name.clone()];
    let mut namespace = row.namespace.clone();
    let mut current = index;
    for _ in 0..64 {
        let Some(owner) = nested.get(&current).copied() else {
            break;
        };
        let Some(owner_row) = all.get(owner.saturating_sub(1) as usize) else {
            return String::new();
        };
        parts.push(owner_row.name.clone());
        namespace = owner_row.namespace.clone();
        current = owner;
    }
    if nested.contains_key(&current) {
        return String::new();
    }
    parts.reverse();
    if namespace.is_empty() {
        parts.join(".")
    } else {
        format!("{}.{}", namespace, parts.join("."))
    }
}
fn resolve_typedef_or_ref(
    value: u32,
    types: &[TypeRow],
    type_refs: &[TypeRefRow],
    type_specs: &[TypeSpecRow],
) -> String {
    resolve_typedef_or_ref_at_depth(value, types, type_refs, type_specs, 0)
}
fn resolve_typedef_or_ref_at_depth(
    value: u32,
    types: &[TypeRow],
    type_refs: &[TypeRefRow],
    type_specs: &[TypeSpecRow],
    depth: usize,
) -> String {
    if depth >= MAX_SIGNATURE_DEPTH {
        return String::new();
    }
    let tag = value & 3;
    let index = (value >> 2) as usize;
    match tag {
        0 => types
            .get(index.saturating_sub(1))
            .map(|r| {
                if r.namespace.is_empty() {
                    r.name.clone()
                } else {
                    format!("{}.{}", r.namespace, r.name)
                }
            })
            .unwrap_or_default(),
        1 => type_ref_name(index, type_refs),
        2 => {
            let Some(spec) = type_specs.get(index.saturating_sub(1)) else {
                return String::new();
            };
            let mut cursor = 0;
            decode_type_at_depth(
                &spec.sig,
                &mut cursor,
                types,
                type_refs,
                type_specs,
                depth + 1,
            )
            .unwrap_or_default()
        }
        _ => String::new(),
    }
}
fn type_ref_name(index: usize, type_refs: &[TypeRefRow]) -> String {
    let mut current = index;
    let mut names = Vec::new();
    for _ in 0..type_refs.len() {
        let Some(row) = type_refs.get(current.saturating_sub(1)) else {
            return String::new();
        };
        names.push(row.name.clone());
        if row.scope & 3 != 3 {
            names.reverse();
            return if row.namespace.is_empty() {
                names.join(".")
            } else {
                format!("{}.{}", row.namespace, names.join("."))
            };
        }
        current = (row.scope >> 2) as usize;
    }
    String::new()
}
fn type_visibility(flags: u32) -> CSharpVisibility {
    match flags & 7 {
        1 | 2 => CSharpVisibility::Public,
        3 => CSharpVisibility::Private,
        4 => CSharpVisibility::Protected,
        5 => CSharpVisibility::Internal,
        6 => CSharpVisibility::ProtectedAndInternal,
        7 => CSharpVisibility::ProtectedOrInternal,
        _ => CSharpVisibility::Internal,
    }
}
fn member_visibility(flags: u16) -> CSharpVisibility {
    match flags & 7 {
        1 => CSharpVisibility::Private,
        2 => CSharpVisibility::ProtectedAndInternal,
        3 => CSharpVisibility::Internal,
        4 => CSharpVisibility::Protected,
        5 => CSharpVisibility::ProtectedOrInternal,
        6 => CSharpVisibility::Public,
        _ => CSharpVisibility::Private,
    }
}
fn decode_signature(
    blob: &[u8],
    method: bool,
    types: &[TypeRow],
    type_refs: &[TypeRefRow],
    type_specs: &[TypeSpecRow],
) -> (Option<String>, Vec<String>, usize) {
    let mut p = 0;
    let Some(header) = blob.get(p).copied() else {
        return (None, Vec::new(), 0);
    };
    p += 1;
    let generic = if header & 0x10 != 0 {
        compressed(blob, &mut p).unwrap_or(0) as usize
    } else {
        0
    };
    let count = if method || header & 0x0f == 0x08 {
        compressed(blob, &mut p).unwrap_or(0) as usize
    } else {
        0
    };
    let ret = decode_type(blob, &mut p, types, type_refs, type_specs);
    let mut params = Vec::new();
    for _ in 0..count {
        if let Some(value) = decode_type(blob, &mut p, types, type_refs, type_specs) {
            params.push(value);
        }
    }
    (ret, params, generic)
}
fn decode_type(
    blob: &[u8],
    p: &mut usize,
    types: &[TypeRow],
    type_refs: &[TypeRefRow],
    type_specs: &[TypeSpecRow],
) -> Option<String> {
    decode_type_at_depth(blob, p, types, type_refs, type_specs, 0)
}
fn decode_type_at_depth(
    blob: &[u8],
    p: &mut usize,
    types: &[TypeRow],
    type_refs: &[TypeRefRow],
    type_specs: &[TypeSpecRow],
    depth: usize,
) -> Option<String> {
    if depth >= MAX_SIGNATURE_DEPTH {
        return None;
    }
    let element = *blob.get(*p)?;
    *p += 1;
    let primitive = match element {
        0x01 => "void",
        0x02 => "bool",
        0x03 => "char",
        0x04 => "sbyte",
        0x05 => "byte",
        0x06 => "short",
        0x07 => "ushort",
        0x08 => "int",
        0x09 => "uint",
        0x0a => "long",
        0x0b => "ulong",
        0x0c => "float",
        0x0d => "double",
        0x0e => "string",
        0x18 => "IntPtr",
        0x19 => "UIntPtr",
        0x1c => "object",
        _ => "",
    };
    if !primitive.is_empty() {
        return Some(primitive.to_string());
    }
    match element {
        0x0f => decode_type_at_depth(blob, p, types, type_refs, type_specs, depth + 1)
            .map(|v| format!("{v}*")),
        0x10 => decode_type_at_depth(blob, p, types, type_refs, type_specs, depth + 1)
            .map(|v| format!("{v}&")),
        0x1d => decode_type_at_depth(blob, p, types, type_refs, type_specs, depth + 1)
            .map(|v| format!("{v}[]")),
        0x11 | 0x12 => compressed(blob, p)
            .map(|v| resolve_typedef_or_ref_at_depth(v, types, type_refs, type_specs, depth + 1)),
        0x13 => compressed(blob, p).map(|v| format!("!{v}")),
        0x1e => compressed(blob, p).map(|v| format!("!!{v}")),
        0x14 => {
            let inner = decode_type_at_depth(blob, p, types, type_refs, type_specs, depth + 1)?;
            let rank = compressed(blob, p)?;
            let sizes = compressed(blob, p)?;
            for _ in 0..sizes {
                compressed(blob, p)?;
            }
            let lowers = compressed(blob, p)?;
            for _ in 0..lowers {
                compressed(blob, p)?;
            }
            Some(format!(
                "{inner}[{}]",
                ",".repeat(rank.saturating_sub(1) as usize)
            ))
        }
        0x15 => {
            let _ = blob.get(*p)?;
            *p += 1;
            let base = resolve_typedef_or_ref_at_depth(
                compressed(blob, p)?,
                types,
                type_refs,
                type_specs,
                depth + 1,
            );
            let count = compressed(blob, p)?;
            let mut arguments = Vec::new();
            for _ in 0..count {
                arguments.push(decode_type_at_depth(
                    blob,
                    p,
                    types,
                    type_refs,
                    type_specs,
                    depth + 1,
                )?);
            }
            (!base.is_empty()).then(|| format!("{base}<{}>", arguments.join(", ")))
        }
        0x1f | 0x20 => {
            compressed(blob, p)?;
            decode_type_at_depth(blob, p, types, type_refs, type_specs, depth + 1)
        }
        _ => None,
    }
}
fn compressed(bytes: &[u8], p: &mut usize) -> Option<u32> {
    let first = *bytes.get(*p)?;
    *p += 1;
    if first & 0x80 == 0 {
        return Some(first as u32);
    }
    if first & 0xc0 == 0x80 {
        let second = *bytes.get(*p)?;
        *p += 1;
        return Some((((first & 0x3f) as u32) << 8) | second as u32);
    }
    if first & 0xe0 == 0xc0 {
        let rest = take(bytes, p, 3)?;
        return Some(
            (((first & 0x1f) as u32) << 24)
                | ((rest[0] as u32) << 16)
                | ((rest[1] as u32) << 8)
                | rest[2] as u32,
        );
    }
    None
}
fn row_size(table: usize, rows: &[u32; 45], heap: u8) -> Option<usize> {
    let s = if heap & 1 != 0 { 4 } else { 2 };
    let g = if heap & 2 != 0 { 4 } else { 2 };
    let b = if heap & 4 != 0 { 4 } else { 2 };
    let ix = |t| index_size(rows[t]);
    let c = |tables: &[usize], bits| coded_size(rows, tables, bits);
    Some(match table {
        0 => 2 + s + g * 3,
        1 => c(&[0, 26, 35, 1], 2) + s * 2,
        2 => 4 + s * 2 + c(&[2, 1, 27], 2) + ix(4) + ix(6),
        3 => ix(4),
        4 => 2 + s + b,
        5 => ix(6),
        6 => 8 + s + b + ix(8),
        7 => ix(8),
        8 => 4 + s,
        9 => ix(2) + c(&[2, 1, 27], 2),
        10 => c(&[2, 1, 26, 6, 27], 3) + s + b,
        11 => 2 + c(&[4, 8, 23], 2) + b,
        12 => {
            c(
                &[
                    6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43,
                ],
                5,
            ) + c(&[6, 10], 3)
                + b
        }
        13 => c(&[4, 8], 1) + b,
        14 => 2 + c(&[2, 6, 32], 2) + b,
        15 => 2 + 4 + ix(2),
        16 => 4 + ix(4),
        17 => b,
        18 => ix(2) + ix(20),
        19 => ix(20),
        20 => 2 + s + c(&[2, 1, 27], 2),
        21 => ix(2) + ix(23),
        22 => ix(23),
        23 => 2 + s + b,
        24 => 2 + ix(6) + c(&[20, 23], 1),
        25 => ix(2) + c(&[6, 10], 1) * 2,
        26 => s,
        27 => b,
        28 => 2 + c(&[4, 6], 1) + s + ix(26),
        29 => 4 + ix(4),
        30 => 8,
        31 => 4,
        32 => 16 + b + s * 2,
        33 => 4,
        34 => 12,
        35 => 12 + b + s * 2 + b,
        36 => 4 + ix(35),
        37 => 12 + ix(35),
        38 => 4 + s + b,
        39 => 8 + s * 2 + c(&[38, 35, 39], 2),
        40 => 8 + s + c(&[38, 35, 39], 2),
        41 => ix(2) * 2,
        42 => 4 + c(&[2, 6], 1) + s,
        43 => c(&[6, 10], 1) + b,
        44 => ix(42) + c(&[2, 1, 27], 2),
        _ => return None,
    })
}
fn index_size(rows: u32) -> usize {
    if rows < 0x10000 { 2 } else { 4 }
}
fn coded_size(rows: &[u32; 45], tables: &[usize], bits: u32) -> usize {
    if tables.iter().any(|&t| rows[t] >= (1 << (16 - bits))) {
        4
    } else {
        2
    }
}
fn take<'a>(bytes: &'a [u8], p: &mut usize, n: usize) -> Option<&'a [u8]> {
    let out = bytes.get(*p..p.checked_add(n)?)?;
    *p += n;
    Some(out)
}
fn u16at(b: &[u8], p: &mut usize) -> Option<u16> {
    Some(u16::from_le_bytes(take(b, p, 2)?.try_into().ok()?))
}
fn u32at(b: &[u8], p: &mut usize) -> Option<u32> {
    Some(u32::from_le_bytes(take(b, p, 4)?.try_into().ok()?))
}
fn u64at(b: &[u8], p: &mut usize) -> Option<u64> {
    Some(u64::from_le_bytes(take(b, p, 8)?.try_into().ok()?))
}
fn index(b: &[u8], p: &mut usize, size: usize) -> Option<u32> {
    if size == 2 {
        u16at(b, p).map(u32::from)
    } else {
        u32at(b, p)
    }
}
fn str_index(b: &[u8], p: &mut usize, heap: u8, strings: &[u8]) -> Option<String> {
    let idx = index(b, p, if heap & 1 != 0 { 4 } else { 2 })? as usize;
    if idx == 0 {
        return Some(String::new());
    }
    let end = strings.get(idx..)?.iter().position(|v| *v == 0)? + idx;
    std::str::from_utf8(strings.get(idx..end)?)
        .ok()
        .map(str::to_string)
}
fn blob_index(b: &[u8], p: &mut usize, heap: u8, blobs: &[u8]) -> Option<Vec<u8>> {
    let idx = index(b, p, if heap & 4 != 0 { 4 } else { 2 })? as usize;
    if idx == 0 {
        return Some(Vec::new());
    }
    let mut start = idx;
    let len = compressed(blobs, &mut start)? as usize;
    blobs
        .get(start..start.checked_add(len)?)
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    const DLL: &[u8] =
        include_bytes!("../../../tests/fixtures/csharp-external/ExternalLibrary.dll");
    const SHA: &str =
        include_str!("../../../tests/fixtures/csharp-external/ExternalLibrary.dll.sha256");

    #[test]
    fn external_fixture_is_pinned_and_exposes_members() {
        let actual = format!("{:x}", Sha256::digest(DLL));
        let expected = SHA.split_whitespace().next().unwrap();
        assert_eq!(
            actual, expected,
            "C# fixture DLL changed; rebuild it through the fixture verifier"
        );
        let pe = PE::parse(DLL).expect("fixture PE");
        let metadata = metadata_bytes(&pe, DLL).expect("fixture metadata");
        let streams = Streams::parse(metadata).expect("fixture streams");
        assert!(
            TableLayout::parse(streams.tables.expect("fixture tables")).is_some(),
            "fixture table layout"
        );
        let layout = TableLayout::parse(streams.tables.expect("fixture tables")).unwrap();
        assert!(
            (1..=layout.rows(2))
                .all(|i| read_typedef(&layout, i, streams.strings.unwrap()).is_some()),
            "fixture type definitions"
        );
        assert!(
            (1..=layout.rows(4)).all(|i| {
                read_field(&layout, i, streams.strings.unwrap(), streams.blobs.unwrap()).is_some()
            }),
            "fixture fields"
        );
        assert!(
            (1..=layout.rows(6)).all(|i| {
                read_method(&layout, i, streams.strings.unwrap(), streams.blobs.unwrap()).is_some()
            }),
            "fixture methods"
        );
        assert!(
            (1..=layout.rows(23)).all(|i| {
                read_property(&layout, i, streams.strings.unwrap(), streams.blobs.unwrap())
                    .is_some()
            }),
            "fixture properties"
        );
        let types = parse_assembly(Path::new("ExternalLibrary.dll"), DLL)
            .expect("fixture must be a managed assembly");
        let client = types
            .iter()
            .find(|ty| ty.fqn() == "Fixture.Api.Client`1")
            .expect("generic public class");
        assert!(
            client
                .members()
                .iter()
                .any(|member| member.name() == "Send")
        );
        assert!(
            client
                .members()
                .iter()
                .any(|member| member.name() == "Name")
        );
        let name = client
            .members()
            .iter()
            .find(|member| member.name() == "Name")
            .unwrap();
        assert_eq!(name.kind(), CSharpExternalMemberKind::Property);
        assert_eq!(name.visibility(), CSharpVisibility::Public);
        assert_eq!(name.return_type(), Some("string"));
        assert!(matches!(
            name.source(),
            CSharpExternalDeclarationSource::Assembly { metadata_token, .. }
                if *metadata_token & 0xff00_0000 == 0x1700_0000
        ));
        assert!(matches!(
            types.iter().find(|ty| ty.fqn() == "Fixture.Api.Message"),
            Some(ty) if ty.kind() == CSharpExternalTypeKind::Struct
        ));
        assert!(matches!(
            types.iter().find(|ty| ty.fqn() == "Fixture.Api.Status"),
            Some(ty) if ty.kind() == CSharpExternalTypeKind::Enum
        ));
        assert!(matches!(
            types.iter().find(|ty| ty.fqn() == "Fixture.Api.MessageHandler"),
            Some(ty) if ty.kind() == CSharpExternalTypeKind::Delegate
        ));
        let generic_surface = types
            .iter()
            .find(|ty| ty.fqn() == "Fixture.Api.GenericSurface")
            .expect("constructed generic metadata surface");
        assert!(
            generic_surface
                .interfaces()
                .iter()
                .any(|interface| interface.contains("IEnumerable`1<Fixture.Api.Message>"))
        );
        assert!(generic_surface.members().iter().any(|member| {
            member.name() == "Lookup"
                && member
                    .return_type()
                    .is_some_and(|ty| ty.contains("Dictionary`2<string"))
        }));
    }

    #[test]
    fn malformed_input_is_ignored() {
        assert!(parse_assembly(Path::new("bad.dll"), b"not a PE").is_none());
    }

    #[test]
    fn typespec_generic_instances_preserve_base_and_arguments() {
        let refs = vec![TypeRefRow {
            scope: 0,
            name: "List`1".to_string(),
            namespace: "System.Collections.Generic".to_string(),
        }];
        let specs = vec![TypeSpecRow {
            // GENERICINST CLASS TypeRef(1) one argument: string.
            sig: vec![0x15, 0x12, 0x05, 0x01, 0x0e],
        }];
        assert_eq!(
            resolve_typedef_or_ref(0x06, &[], &refs, &specs),
            "System.Collections.Generic.List`1<string>"
        );
    }

    #[test]
    fn cyclic_typespec_is_undecodable_without_recursing_unboundedly() {
        let specs = vec![TypeSpecRow {
            // GENERICINST CLASS TypeSpec(1), with no generic arguments.
            sig: vec![0x15, 0x12, 0x06, 0x00],
        }];
        assert!(resolve_typedef_or_ref(0x06, &[], &[], &specs).is_empty());
    }

    #[test]
    fn explicit_assembly_queries_honor_using_aliases_and_generic_identity() {
        let temp = tempfile::tempdir().unwrap();
        let assembly = temp.path().join("ExternalLibrary.dll");
        std::fs::write(&assembly, DLL).unwrap();
        let source = temp.path().join("Probe.cs");
        std::fs::write(&source, "namespace Consumer; class Probe {}\n").unwrap();
        let project =
            crate::analyzer::TestProject::new(temp.path(), crate::analyzer::Language::CSharp);
        let index = CSharpExternalDeclarationIndex::build_for_project(
            &CSharpAnalyzerConfig {
                assembly_paths: vec![assembly.clone()],
            },
            &project,
        );

        let mut aliases = HashMap::default();
        aliases.insert("Api".to_string(), "Fixture.Api".to_string());
        let candidates = index.resolve_in_file("Api::Client<int>", "Consumer", &[], &aliases);
        assert_eq!(candidates.len(), 1);
        let client = candidates[0];
        assert_eq!(client.fqn(), "Fixture.Api.Client`1");
        assert!(matches!(
            client.source(),
            CSharpExternalDeclarationSource::Assembly { path, metadata_token }
                if path == &assembly && *metadata_token == 0x0200_0003
        ));
        assert!(
            index
                .resolve_in_file("InternalOnly", "Fixture.Api", &[], &HashMap::default())
                .is_empty()
        );
        assert_eq!(index.members_named(client.fqn(), "Send").len(), 1);
    }

    #[test]
    fn assets_discovery_retains_candidates_from_multiple_targets() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("Probe.cs"), "class Probe {}\n").unwrap();
        let packages = temp.path().join(".nuget/packages");
        for package in ["fixture-one", "fixture-two"] {
            let assembly = packages
                .join(package)
                .join("1.0.0/ref/net8.0/ExternalLibrary.dll");
            std::fs::create_dir_all(assembly.parent().unwrap()).unwrap();
            std::fs::write(assembly, DLL).unwrap();
        }
        let obj = temp.path().join("obj");
        std::fs::create_dir_all(&obj).unwrap();
        std::fs::write(
            obj.join("project.assets.json"),
            serde_json::json!({
                "packageFolders": { format!("{}/", packages.display()): {} },
                "targets": {
                    "net8.0": {
                        "fixture-one/1.0.0": { "ref": { "ref/net8.0/ExternalLibrary.dll": {} } },
                    },
                    "net9.0": {
                        "fixture-two/1.0.0": { "compile": { "ref/net8.0/ExternalLibrary.dll": {} } },
                    },
                },
            })
            .to_string(),
        )
        .unwrap();
        let project =
            crate::analyzer::TestProject::new(temp.path(), crate::analyzer::Language::CSharp);
        let index = CSharpExternalDeclarationIndex::build_for_project(
            &CSharpAnalyzerConfig::default(),
            &project,
        );
        assert_eq!(
            index
                .resolve_in_file("Fixture.Api.Status", "", &[], &HashMap::default())
                .len(),
            2
        );
    }

    #[test]
    fn assets_discovery_finds_referenced_project_outputs() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("Probe.cs"), "class Probe {}\n").unwrap();
        let project = temp.path().join("projects/Referenced");
        std::fs::create_dir_all(project.join("bin/Debug/net8.0")).unwrap();
        std::fs::write(project.join("Referenced.csproj"), "<Project />").unwrap();
        std::fs::write(project.join("bin/Debug/net8.0/ExternalLibrary.dll"), DLL).unwrap();
        let obj = temp.path().join("obj");
        std::fs::create_dir_all(&obj).unwrap();
        std::fs::write(
            obj.join("project.assets.json"),
            serde_json::json!({
                "targets": { "net8.0": {
                    "Referenced/1.0.0": { "compile": { "bin/placeholder/ExternalLibrary.dll": {} } }
                } },
                "libraries": { "Referenced/1.0.0": {
                    "type": "project", "path": "projects/Referenced/Referenced.csproj"
                } }
            })
            .to_string(),
        )
        .unwrap();
        let project =
            crate::analyzer::TestProject::new(temp.path(), crate::analyzer::Language::CSharp);
        let index = CSharpExternalDeclarationIndex::build_for_project(
            &CSharpAnalyzerConfig::default(),
            &project,
        );
        assert_eq!(
            index
                .resolve_in_file("Fixture.Api.Status", "", &[], &HashMap::default())
                .len(),
            1
        );
    }
}
