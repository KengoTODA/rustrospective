use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result};
use jclassfile::class_file;
use jclassfile::constant_pool::ConstantPool;
use jclassfile::fields::FieldFlags;
use jclassfile::methods::MethodFlags;
use jdescriptor::{MethodDescriptor, TypeDescriptor};
use serde_json::Value;
use serde_sarif::sarif::{Artifact, ArtifactLocation, ArtifactRoles};
use zip::ZipArchive;

use crate::cfg::build_cfg;
use crate::descriptor::method_param_count;
use crate::ir::{
    CallKind, CallSite, Class, ExceptionHandler, Field, FieldAccess, Instruction, InstructionKind,
    LineNumber, Method, MethodAccess, MethodNullness, Nullness,
};
use crate::opcodes;

/// Snapshot of parsed artifacts, classes, and counts for a scan.
pub(crate) struct ScanOutput {
    pub(crate) artifacts: Vec<Artifact>,
    pub(crate) class_count: usize,
    pub(crate) classes: Vec<Class>,
}

pub(crate) fn scan_inputs(input: &Path, classpath: &[PathBuf]) -> Result<ScanOutput> {
    let mut artifacts = Vec::new();
    let mut class_count = 0;
    let mut classes = Vec::new();

    scan_path(
        input,
        true,
        true,
        &mut artifacts,
        &mut class_count,
        &mut classes,
    )?;

    // Keep deterministic ordering by sorting classpath entries and directory listings.
    let mut classpath_entries = classpath.to_vec();
    classpath_entries.sort_by(|a, b| path_key(a).cmp(&path_key(b)));

    if is_jar_path(input) {
        classpath_entries.extend(manifest_classpath(input)?);
    }

    let expanded = expand_classpath(classpath_entries)?;
    for entry in expanded {
        if entry == input {
            continue;
        }
        scan_path(
            &entry,
            false,
            true,
            &mut artifacts,
            &mut class_count,
            &mut classes,
        )?;
    }

    Ok(ScanOutput {
        artifacts,
        class_count,
        classes,
    })
}

fn scan_path(
    path: &Path,
    is_input: bool,
    strict: bool,
    artifacts: &mut Vec<Artifact>,
    class_count: &mut usize,
    classes: &mut Vec<Class>,
) -> Result<()> {
    if path.is_dir() {
        scan_dir(path, artifacts, class_count, classes)?;
        return Ok(());
    }

    let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    let roles = if is_input {
        Some(vec![
            serde_json::to_value(ArtifactRoles::AnalysisTarget).expect("serialize artifact role"),
        ])
    } else {
        None
    };

    match extension {
        "class" => scan_class_file(path, roles, artifacts, class_count, classes),
        "jar" => scan_jar_file(path, roles, artifacts, class_count, classes),
        _ => {
            if strict {
                anyhow::bail!("unsupported input file: {}", path.display())
            } else {
                Ok(())
            }
        }
    }
}

fn scan_dir(
    path: &Path,
    artifacts: &mut Vec<Artifact>,
    class_count: &mut usize,
    classes: &mut Vec<Class>,
) -> Result<()> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(path)
        .with_context(|| format!("failed to read directory {}", path.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to read entry under {}", path.display()))?;
        entries.push(entry.path());
    }

    entries.sort_by(|a, b| path_key(a).cmp(&path_key(b)));

    for entry in entries {
        if entry.is_dir() {
            scan_dir(&entry, artifacts, class_count, classes)?;
        } else {
            scan_path(&entry, false, false, artifacts, class_count, classes)?;
        }
    }

    Ok(())
}

fn scan_class_file(
    path: &Path,
    roles: Option<Vec<Value>>,
    artifacts: &mut Vec<Artifact>,
    class_count: &mut usize,
    classes: &mut Vec<Class>,
) -> Result<()> {
    let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let parsed =
        parse_class_bytes(&data).with_context(|| format!("failed to parse {}", path.display()))?;
    *class_count += 1;

    let artifact_index = if roles.is_some() {
        push_path_artifact(path, roles, data.len() as u64, None, artifacts)?
    } else {
        -1
    };
    classes.push(Class {
        name: parsed.name,
        super_name: parsed.super_name,
        interfaces: parsed.interfaces,
        referenced_classes: parsed.referenced_classes,
        fields: parsed.fields,
        methods: parsed.methods,
        artifact_index,
        is_record: parsed.is_record,
    });
    Ok(())
}

fn scan_jar_file(
    path: &Path,
    roles: Option<Vec<Value>>,
    artifacts: &mut Vec<Artifact>,
    class_count: &mut usize,
    classes: &mut Vec<Class>,
) -> Result<()> {
    let file =
        fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut archive =
        ZipArchive::new(file).with_context(|| format!("failed to read {}", path.display()))?;

    let jar_len = fs::metadata(path)
        .with_context(|| format!("failed to read {}", path.display()))?
        .len();
    let jar_index = push_path_artifact(path, roles, jar_len, None, artifacts)?;

    let mut entry_names = Vec::new();
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_string();
        // TODO: Handle multi-release entries under META-INF/versions/ in a future release.
        if name.ends_with(".class")
            && !name.ends_with("module-info.class")
            && !name.starts_with("META-INF/versions/")
        {
            entry_names.push(name);
        }
    }

    entry_names.sort();

    for name in entry_names {
        if name.starts_with("META-INF/versions/") {
            continue;
        }
        let mut entry = archive
            .by_name(&name)
            .with_context(|| format!("failed to read {}:{}", path.display(), name))?;
        let mut data = Vec::new();
        entry
            .read_to_end(&mut data)
            .with_context(|| format!("failed to read {}:{}", path.display(), name))?;
        let parsed = parse_class_bytes(&data)
            .with_context(|| format!("failed to parse {}:{}", path.display(), name))?;
        *class_count += 1;

        classes.push(Class {
            name: parsed.name,
            super_name: parsed.super_name,
            interfaces: parsed.interfaces,
            referenced_classes: parsed.referenced_classes,
            fields: parsed.fields,
            methods: parsed.methods,
            artifact_index: jar_index,
            is_record: parsed.is_record,
        });
    }

    Ok(())
}

/// Push a path-based artifact and return its index for parent linkage (e.g., JAR entries).
fn push_path_artifact(
    path: &Path,
    roles: Option<Vec<Value>>,
    len: u64,
    parent_index: Option<i64>,
    artifacts: &mut Vec<Artifact>,
) -> Result<i64> {
    let uri = path_to_uri(path);
    Ok(push_artifact(uri, len, parent_index, roles, artifacts))
}

fn push_artifact(
    uri: String,
    len: u64,
    parent_index: Option<i64>,
    roles: Option<Vec<Value>>,
    artifacts: &mut Vec<Artifact>,
) -> i64 {
    let location = ArtifactLocation::builder().uri(uri).build();
    let artifact = match (parent_index, roles) {
        (Some(parent_index), Some(roles)) => Artifact::builder()
            .location(location)
            .length(len as i64)
            .parent_index(parent_index)
            .roles(roles)
            .build(),
        (Some(parent_index), None) => Artifact::builder()
            .location(location)
            .length(len as i64)
            .parent_index(parent_index)
            .build(),
        (None, Some(roles)) => Artifact::builder()
            .location(location)
            .length(len as i64)
            .roles(roles)
            .build(),
        (None, None) => Artifact::builder()
            .location(location)
            .length(len as i64)
            .build(),
    };
    let index = artifacts.len() as i64;
    artifacts.push(artifact);
    index
}

fn path_to_uri(path: &Path) -> String {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    format!("file://{}", absolute.to_string_lossy())
}

fn path_key(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn expand_classpath(initial: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    let mut queue = VecDeque::new();
    let mut initial_sorted = initial;
    initial_sorted.sort_by(|a, b| path_key(a).cmp(&path_key(b)));
    for entry in initial_sorted {
        queue.push_back(entry);
    }

    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    while let Some(entry) = queue.pop_front() {
        let key = path_key(&entry);
        if !seen.insert(key) {
            continue;
        }
        if !entry.exists() {
            anyhow::bail!("classpath entry not found: {}", entry.display());
        }
        result.push(entry.clone());
        if is_jar_path(&entry) {
            let mut referenced = manifest_classpath(&entry)?;
            referenced.sort_by(|a, b| path_key(a).cmp(&path_key(b)));
            for item in referenced {
                queue.push_back(item);
            }
        }
    }

    Ok(result)
}

fn manifest_classpath(path: &Path) -> Result<Vec<PathBuf>> {
    let file =
        fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut archive =
        ZipArchive::new(file).with_context(|| format!("failed to read {}", path.display()))?;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if entry.name() != "META-INF/MANIFEST.MF" {
            continue;
        }
        let mut content = String::new();
        entry
            .read_to_string(&mut content)
            .with_context(|| format!("failed to read {}", entry.name()))?;
        return Ok(parse_manifest_classpath(path, &content));
    }

    Ok(Vec::new())
}

fn parse_manifest_classpath(jar_path: &Path, content: &str) -> Vec<PathBuf> {
    let mut class_path = None;
    let mut current_key = None;
    let mut current_value = String::new();

    for raw_line in content.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.starts_with(' ') {
            if current_key.is_some() {
                current_value.push_str(&line[1..]);
            }
            continue;
        }

        if let Some(key) = current_key.take() {
            if key == "Class-Path" {
                class_path = Some(current_value.clone());
            }
            current_value.clear();
        }

        if let Some((key, value)) = line.split_once(':') {
            current_key = Some(key.trim().to_string());
            current_value.push_str(value.trim_start());
        }
    }

    if let Some(key) = current_key.take() {
        if key == "Class-Path" {
            class_path = Some(current_value.clone());
        }
    }

    let Some(class_path) = class_path else {
        return Vec::new();
    };

    let base_dir = jar_path.parent().unwrap_or_else(|| Path::new(""));
    class_path
        .split_whitespace()
        .map(|entry| {
            let entry_path = PathBuf::from(entry);
            if entry_path.is_absolute() {
                entry_path
            } else {
                base_dir.join(entry_path)
            }
        })
        .collect()
}

fn is_jar_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("jar"))
        .unwrap_or(false)
}

/// Parsed class data extracted from class file bytes.
struct ParsedClass {
    name: String,
    super_name: Option<String>,
    interfaces: Vec<String>,
    referenced_classes: Vec<String>,
    fields: Vec<crate::ir::Field>,
    methods: Vec<Method>,
    is_record: bool,
}

fn parse_class_bytes(data: &[u8]) -> Result<ParsedClass> {
    let class_file = match class_file::parse(data) {
        Ok(parsed) => parsed,
        Err(err) => {
            let message = format!("{err}");
            if message.contains("unmatched attribute") {
                return parse_class_bytes_minimal(data).context("failed to parse class file bytes");
            }
            return Err(err).context("failed to parse class file bytes");
        }
    };
    let constant_pool = class_file.constant_pool();
    let class_name =
        resolve_class_name(constant_pool, class_file.this_class()).context("resolve class name")?;
    let super_name = if class_file.super_class() == 0 {
        None
    } else {
        Some(
            resolve_class_name(constant_pool, class_file.super_class())
                .context("resolve super class name")?,
        )
    };
    let mut interfaces = Vec::new();
    for interface in class_file.interfaces() {
        interfaces
            .push(resolve_class_name(constant_pool, *interface).context("resolve interface name")?);
    }

    let mut referenced = std::collections::BTreeSet::new();
    for entry in constant_pool {
        if let ConstantPool::Class { name_index } = entry {
            let name = resolve_utf8(constant_pool, *name_index)
                .context("resolve referenced class name")?;
            if let Some(normalized) = normalize_class_name(&name) {
                referenced.insert(normalized);
            }
        }
    }
    referenced.remove(&class_name);

    let is_record = class_file
        .attributes()
        .iter()
        .any(|attr| matches!(attr, jclassfile::attributes::Attribute::Record { .. }));
    let fields = parse_fields(constant_pool, class_file.fields()).context("parse fields")?;
    let default_nullness = parse_default_nullness(class_file.attributes(), constant_pool)
        .context("parse class nullness")?;
    let methods = parse_methods(constant_pool, class_file.methods(), default_nullness)
        .context("parse method bytecode")?;

    Ok(ParsedClass {
        name: class_name,
        super_name,
        interfaces,
        referenced_classes: referenced.into_iter().collect(),
        fields,
        methods,
        is_record,
    })
}

fn resolve_class_name(constant_pool: &[ConstantPool], class_index: u16) -> Result<String> {
    let entry = constant_pool
        .get(class_index as usize)
        .context("missing class entry")?;
    match entry {
        ConstantPool::Class { name_index } => resolve_utf8(constant_pool, *name_index),
        _ => anyhow::bail!("unexpected class entry"),
    }
}

fn resolve_utf8(constant_pool: &[ConstantPool], index: u16) -> Result<String> {
    let entry = constant_pool
        .get(index as usize)
        .context("missing utf8 entry")?;
    match entry {
        ConstantPool::Utf8 { value } => Ok(value.clone()),
        _ => anyhow::bail!("unexpected utf8 entry"),
    }
}

fn normalize_class_name(raw: &str) -> Option<String> {
    if !raw.starts_with('[') {
        return Some(raw.to_string());
    }
    let mut slice = raw;
    while let Some(rest) = slice.strip_prefix('[') {
        slice = rest;
    }
    if let Some(class_name) = slice.strip_prefix('L').and_then(|s| s.strip_suffix(';')) {
        return Some(class_name.to_string());
    }
    None
}

fn parse_class_bytes_minimal(data: &[u8]) -> Result<ParsedClass> {
    let mut offset = 0usize;
    let magic = read_u32_class(data, &mut offset)?;
    if magic != 0xCAFEBABE {
        anyhow::bail!("invalid class file magic");
    }
    let _minor = read_u16_class(data, &mut offset)?;
    let _major = read_u16_class(data, &mut offset)?;
    let (cp_entries, class_entries) = parse_constant_pool_minimal(data, &mut offset)?;
    let _access_flags = read_u16_class(data, &mut offset)?;
    let this_class = read_u16_class(data, &mut offset)?;
    let super_class = read_u16_class(data, &mut offset)?;

    let class_name = resolve_class_name_minimal(&cp_entries, &class_entries, this_class)
        .context("resolve class name")?;
    let super_name = if super_class == 0 {
        None
    } else {
        Some(
            resolve_class_name_minimal(&cp_entries, &class_entries, super_class)
                .context("resolve super class name")?,
        )
    };

    let interfaces = parse_interfaces_minimal(data, &mut offset, &cp_entries, &class_entries)?;
    skip_fields(data, &mut offset)?;
    skip_methods(data, &mut offset)?;
    skip_attributes(data, &mut offset)?;

    let mut referenced = std::collections::BTreeSet::new();
    for (index, name_index) in class_entries.iter().enumerate() {
        if name_index.is_none() {
            continue;
        }
        let name = resolve_class_name_minimal(&cp_entries, &class_entries, index as u16)?;
        if let Some(normalized) = normalize_class_name(&name) {
            referenced.insert(normalized);
        }
    }
    referenced.remove(&class_name);

    Ok(ParsedClass {
        name: class_name,
        super_name,
        interfaces,
        referenced_classes: referenced.into_iter().collect(),
        fields: Vec::new(),
        methods: Vec::new(),
        is_record: false,
    })
}

#[derive(Clone)]
enum CpEntryMin {
    Utf8(String),
    Other,
}

fn parse_constant_pool_minimal(
    data: &[u8],
    offset: &mut usize,
) -> Result<(Vec<CpEntryMin>, Vec<Option<u16>>)> {
    let count = read_u16_class(data, offset)?;
    let mut entries = Vec::with_capacity(count as usize);
    entries.push(CpEntryMin::Other);
    let mut class_entries = vec![None; count as usize];
    let mut index = 1u16;
    while index < count {
        let tag = read_u8_class(data, offset)?;
        match tag {
            1 => {
                let len = read_u16_class(data, offset)? as usize;
                let bytes = read_bytes_class(data, offset, len)?;
                let value = String::from_utf8_lossy(bytes).to_string();
                entries.push(CpEntryMin::Utf8(value));
            }
            7 => {
                let name_index = read_u16_class(data, offset)?;
                entries.push(CpEntryMin::Other);
                class_entries[index as usize] = Some(name_index);
            }
            3 | 4 => {
                skip_class_bytes(data, offset, 4)?;
                entries.push(CpEntryMin::Other);
            }
            5 | 6 => {
                skip_class_bytes(data, offset, 8)?;
                entries.push(CpEntryMin::Other);
                entries.push(CpEntryMin::Other);
                index += 1;
            }
            8 => {
                skip_class_bytes(data, offset, 2)?;
                entries.push(CpEntryMin::Other);
            }
            9 | 10 | 11 | 12 | 18 => {
                skip_class_bytes(data, offset, 4)?;
                entries.push(CpEntryMin::Other);
            }
            15 => {
                skip_class_bytes(data, offset, 3)?;
                entries.push(CpEntryMin::Other);
            }
            16 | 19 | 20 => {
                skip_class_bytes(data, offset, 2)?;
                entries.push(CpEntryMin::Other);
            }
            17 => {
                skip_class_bytes(data, offset, 4)?;
                entries.push(CpEntryMin::Other);
            }
            _ => anyhow::bail!("unsupported constant pool tag: {}", tag),
        }
        index += 1;
    }
    Ok((entries, class_entries))
}

fn resolve_class_name_minimal(
    entries: &[CpEntryMin],
    class_entries: &[Option<u16>],
    class_index: u16,
) -> Result<String> {
    let entry = class_entries
        .get(class_index as usize)
        .context("missing class entry")?;
    let name_index = entry.context("missing class name index")?;
    match entries.get(name_index as usize) {
        Some(CpEntryMin::Utf8(value)) => Ok(value.clone()),
        _ => anyhow::bail!("missing utf8 entry for class name"),
    }
}

fn parse_interfaces_minimal(
    data: &[u8],
    offset: &mut usize,
    entries: &[CpEntryMin],
    class_entries: &[Option<u16>],
) -> Result<Vec<String>> {
    let count = read_u16_class(data, offset)? as usize;
    let mut interfaces = Vec::with_capacity(count);
    for _ in 0..count {
        let index = read_u16_class(data, offset)?;
        interfaces.push(resolve_class_name_minimal(entries, class_entries, index)?);
    }
    Ok(interfaces)
}

fn skip_fields(data: &[u8], offset: &mut usize) -> Result<()> {
    let count = read_u16_class(data, offset)?;
    for _ in 0..count {
        skip_class_bytes(data, offset, 6)?;
        skip_attributes(data, offset)?;
    }
    Ok(())
}

fn skip_methods(data: &[u8], offset: &mut usize) -> Result<()> {
    let count = read_u16_class(data, offset)?;
    for _ in 0..count {
        skip_class_bytes(data, offset, 6)?;
        skip_attributes(data, offset)?;
    }
    Ok(())
}

fn skip_attributes(data: &[u8], offset: &mut usize) -> Result<()> {
    let count = read_u16_class(data, offset)?;
    for _ in 0..count {
        skip_class_bytes(data, offset, 2)?;
        let length = read_u32_class(data, offset)? as usize;
        skip_class_bytes(data, offset, length)?;
    }
    Ok(())
}

fn read_u8_class(data: &[u8], offset: &mut usize) -> Result<u8> {
    let byte = *data.get(*offset).context("class file out of bounds")?;
    *offset += 1;
    Ok(byte)
}

fn read_u16_class(data: &[u8], offset: &mut usize) -> Result<u16> {
    let bytes = read_bytes_class(data, offset, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32_class(data: &[u8], offset: &mut usize) -> Result<u32> {
    let bytes = read_bytes_class(data, offset, 4)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_bytes_class<'a>(data: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8]> {
    let start = *offset;
    let end = start + len;
    let slice = data.get(start..end).context("class file out of bounds")?;
    *offset = end;
    Ok(slice)
}

fn skip_class_bytes(data: &[u8], offset: &mut usize, len: usize) -> Result<()> {
    read_bytes_class(data, offset, len)?;
    Ok(())
}

fn parse_fields(
    constant_pool: &[ConstantPool],
    fields: &[jclassfile::fields::FieldInfo],
) -> Result<Vec<Field>> {
    let mut parsed = Vec::new();
    for field in fields {
        let name = resolve_utf8(constant_pool, field.name_index()).context("resolve field name")?;
        let descriptor = resolve_utf8(constant_pool, field.descriptor_index())
            .context("resolve field descriptor")?;
        let access_flags = field.access_flags();
        let access = FieldAccess {
            is_static: access_flags.contains(FieldFlags::ACC_STATIC),
        };
        parsed.push(Field {
            name,
            descriptor,
            access,
        });
    }
    Ok(parsed)
}

fn parse_methods(
    constant_pool: &[ConstantPool],
    methods: &[jclassfile::methods::MethodInfo],
    default_nullness: DefaultNullness,
) -> Result<Vec<Method>> {
    let mut parsed = Vec::new();
    for method in methods {
        let name =
            resolve_utf8(constant_pool, method.name_index()).context("resolve method name")?;
        let descriptor = resolve_utf8(constant_pool, method.descriptor_index())
            .context("resolve method descriptor")?;
        let access_flags = method.access_flags();
        let access = MethodAccess {
            is_public: access_flags.contains(MethodFlags::ACC_PUBLIC),
            is_static: access_flags.contains(MethodFlags::ACC_STATIC),
            is_abstract: access_flags.contains(MethodFlags::ACC_ABSTRACT),
        };
        let nullness = parse_method_nullness(
            constant_pool,
            method.attributes(),
            &descriptor,
            default_nullness,
        )
        .context("parse method nullness")?;
        let code = method
            .attributes()
            .iter()
            .find_map(|attribute| match attribute {
                jclassfile::attributes::Attribute::Code {
                    code,
                    exception_table,
                    attributes,
                    ..
                } => Some((code, exception_table, attributes)),
                _ => None,
            });
        let Some((code, exception_table, code_attributes)) = code else {
            continue;
        };
        let line_numbers =
            parse_line_numbers(code_attributes, constant_pool).context("parse line numbers")?;
        let (instructions, calls, string_literals) =
            parse_bytecode(code, constant_pool).context("parse bytecode")?;
        let exception_handlers =
            parse_exception_handlers(exception_table, constant_pool).context("parse handlers")?;
        let handler_offsets = exception_handlers
            .iter()
            .map(|handler| handler.handler_pc)
            .collect::<Vec<_>>();
        let cfg =
            build_cfg(code, &instructions, &handler_offsets).context("build control flow graph")?;
        parsed.push(Method {
            name,
            descriptor,
            access,
            nullness,
            bytecode: code.clone(),
            line_numbers,
            cfg,
            calls,
            string_literals,
            exception_handlers,
        });
    }
    Ok(parsed)
}

fn parse_line_numbers(
    attributes: &[jclassfile::attributes::Attribute],
    _constant_pool: &[ConstantPool],
) -> Result<Vec<LineNumber>> {
    let mut entries = Vec::new();
    for attribute in attributes {
        let jclassfile::attributes::Attribute::LineNumberTable { line_number_table } = attribute
        else {
            continue;
        };
        for record in line_number_table {
            entries.push(LineNumber {
                start_pc: record.start_pc() as u32,
                line: record.line_number() as u32,
            });
        }
    }
    entries.sort_by_key(|entry| entry.start_pc);
    Ok(entries)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DefaultNullness {
    Inherit,
    Unmarked,
    NonNull,
}

fn parse_default_nullness(
    attributes: &[jclassfile::attributes::Attribute],
    constant_pool: &[ConstantPool],
) -> Result<DefaultNullness> {
    let mut has_marked = false;
    let mut has_unmarked = false;
    for attribute in attributes {
        let jclassfile::attributes::Attribute::RuntimeVisibleAnnotations { annotations, .. } =
            attribute
        else {
            continue;
        };
        for annotation in annotations {
            let name = annotation_class_name(constant_pool, annotation)?;
            match name.as_str() {
                "org/jspecify/annotations/NullMarked" => has_marked = true,
                "org/jspecify/annotations/NullUnmarked" => has_unmarked = true,
                _ => {}
            }
        }
    }
    if has_unmarked {
        return Ok(DefaultNullness::Unmarked);
    }
    if has_marked {
        return Ok(DefaultNullness::NonNull);
    }
    Ok(DefaultNullness::Inherit)
}

fn parse_method_nullness(
    constant_pool: &[ConstantPool],
    attributes: &[jclassfile::attributes::Attribute],
    descriptor: &str,
    class_default: DefaultNullness,
) -> Result<MethodNullness> {
    let param_count = method_param_count(descriptor)?;
    let mut nullness = MethodNullness::unknown(param_count);
    for attribute in attributes {
        let jclassfile::attributes::Attribute::RuntimeVisibleTypeAnnotations { type_annotations } =
            attribute
        else {
            continue;
        };
        for annotation in type_annotations {
            if !annotation.type_path().is_empty() {
                continue;
            }
            let Some(value) = nullness_from_annotation(constant_pool, annotation.annotation())?
            else {
                continue;
            };
            match (annotation.target_type(), annotation.target_info()) {
                (
                    jclassfile::attributes::TargetType::METHOD_RETURN,
                    jclassfile::attributes::TargetInfo::EmptyTarget,
                ) => apply_nullness(&mut nullness.return_nullness, value),
                (
                    jclassfile::attributes::TargetType::METHOD_FORMAL_PARAMETER,
                    jclassfile::attributes::TargetInfo::FormalParameterTarget {
                        formal_parameter_index,
                    },
                ) => {
                    let index = *formal_parameter_index as usize;
                    if let Some(param) = nullness.parameter_nullness.get_mut(index) {
                        apply_nullness(param, value);
                    }
                }
                _ => {}
            }
        }
    }
    let method_default = parse_default_nullness(attributes, constant_pool)?;
    let effective_default = match method_default {
        DefaultNullness::Inherit => class_default,
        value => value,
    };
    if effective_default == DefaultNullness::NonNull {
        let descriptor =
            MethodDescriptor::from_str(descriptor).context("parse method descriptor")?;
        for (index, param) in descriptor.parameter_types().iter().enumerate() {
            if is_reference_type(param) {
                if let Some(param_nullness) = nullness.parameter_nullness.get_mut(index) {
                    if *param_nullness == Nullness::Unknown {
                        *param_nullness = Nullness::NonNull;
                    }
                }
            }
        }
        if is_reference_type(descriptor.return_type())
            && nullness.return_nullness == Nullness::Unknown
        {
            nullness.return_nullness = Nullness::NonNull;
        }
    }
    Ok(nullness)
}

fn nullness_from_annotation(
    constant_pool: &[ConstantPool],
    annotation: &jclassfile::attributes::Annotation,
) -> Result<Option<Nullness>> {
    let name = annotation_class_name(constant_pool, annotation)?;
    let value = match name.as_str() {
        "org/jspecify/annotations/Nullable" => Some(Nullness::Nullable),
        "org/jspecify/annotations/NonNull" => Some(Nullness::NonNull),
        "org/jspecify/annotations/NullnessUnspecified" => Some(Nullness::Unknown),
        _ => None,
    };
    Ok(value)
}

fn annotation_class_name(
    constant_pool: &[ConstantPool],
    annotation: &jclassfile::attributes::Annotation,
) -> Result<String> {
    let descriptor =
        resolve_utf8(constant_pool, annotation.type_index()).context("resolve annotation type")?;
    let trimmed = descriptor
        .strip_prefix('L')
        .and_then(|value| value.strip_suffix(';'))
        .context("invalid annotation descriptor")?;
    Ok(trimmed.to_string())
}

fn apply_nullness(target: &mut Nullness, value: Nullness) {
    if *target == Nullness::Unknown {
        *target = value;
        return;
    }
    if *target != value {
        *target = Nullness::Unknown;
    }
}

fn is_reference_type(ty: &TypeDescriptor) -> bool {
    matches!(ty, TypeDescriptor::Object(_) | TypeDescriptor::Array(_, _))
}

fn parse_bytecode(
    code: &[u8],
    constant_pool: &[ConstantPool],
) -> Result<(Vec<Instruction>, Vec<CallSite>, Vec<String>)> {
    let mut instructions = Vec::new();
    let mut calls = Vec::new();
    let mut string_literals = Vec::new();
    let mut offset = 0usize;
    while offset < code.len() {
        let opcode = code[offset];
        let start_offset = offset as u32;
        let length = opcode_length(code, offset)?;
        if length == 0 || offset + length > code.len() {
            anyhow::bail!("invalid bytecode length at offset {}", offset);
        }
        let kind = match opcode {
            opcodes::INVOKEVIRTUAL
            | opcodes::INVOKESPECIAL
            | opcodes::INVOKESTATIC
            | opcodes::INVOKEINTERFACE => {
                let method_index = read_u16(code, offset + 1)?;
                let method_ref = resolve_method_ref(constant_pool, method_index)
                    .context("resolve method ref")?;
                let call_kind = match opcode {
                    opcodes::INVOKEVIRTUAL => CallKind::Virtual,
                    opcodes::INVOKESPECIAL => CallKind::Special,
                    opcodes::INVOKESTATIC => CallKind::Static,
                    opcodes::INVOKEINTERFACE => CallKind::Interface,
                    _ => CallKind::Virtual,
                };
                let call = CallSite {
                    owner: method_ref.owner,
                    name: method_ref.name,
                    descriptor: method_ref.descriptor,
                    kind: call_kind,
                    offset: start_offset,
                };
                calls.push(call.clone());
                InstructionKind::Invoke(call)
            }
            opcodes::LDC => {
                let index = code.get(offset + 1).copied().context("ldc index")? as u16;
                if let Some(value) = resolve_string_literal(constant_pool, index)? {
                    string_literals.push(value.clone());
                    InstructionKind::ConstString(value)
                } else {
                    InstructionKind::Other(opcode)
                }
            }
            opcodes::LDC_W | opcodes::LDC2_W => {
                let index = read_u16(code, offset + 1)?;
                if let Some(value) = resolve_string_literal(constant_pool, index)? {
                    string_literals.push(value.clone());
                    InstructionKind::ConstString(value)
                } else {
                    InstructionKind::Other(opcode)
                }
            }
            _ => InstructionKind::Other(opcode),
        };

        instructions.push(Instruction {
            offset: start_offset,
            opcode,
            kind,
        });
        offset += length;
    }
    Ok((instructions, calls, string_literals))
}

/// Resolved constant pool method reference.
struct MethodRef {
    owner: String,
    name: String,
    descriptor: String,
}

fn resolve_method_ref(constant_pool: &[ConstantPool], index: u16) -> Result<MethodRef> {
    let entry = constant_pool
        .get(index as usize)
        .context("missing method ref entry")?;
    let (class_index, name_and_type_index) = match entry {
        ConstantPool::Methodref {
            class_index,
            name_and_type_index,
        } => (*class_index, *name_and_type_index),
        ConstantPool::InterfaceMethodref {
            class_index,
            name_and_type_index,
        } => (*class_index, *name_and_type_index),
        _ => anyhow::bail!("unexpected method ref entry"),
    };
    let owner = resolve_class_name(constant_pool, class_index).context("resolve owner")?;
    let (name_index, descriptor_index) = resolve_name_and_type(constant_pool, name_and_type_index)?;
    let name = resolve_utf8(constant_pool, name_index).context("resolve method name")?;
    let descriptor =
        resolve_utf8(constant_pool, descriptor_index).context("resolve method descriptor")?;
    Ok(MethodRef {
        owner,
        name,
        descriptor,
    })
}

fn resolve_name_and_type(constant_pool: &[ConstantPool], index: u16) -> Result<(u16, u16)> {
    let entry = constant_pool
        .get(index as usize)
        .context("missing name and type entry")?;
    match entry {
        ConstantPool::NameAndType {
            name_index,
            descriptor_index,
        } => Ok((*name_index, *descriptor_index)),
        _ => anyhow::bail!("unexpected name and type entry"),
    }
}

pub(crate) fn opcode_length(code: &[u8], offset: usize) -> Result<usize> {
    let opcode = code[offset];
    let length = match opcode {
        0x00..=0x0f => 1,
        0x10 => 2,
        0x11 => 3,
        opcodes::LDC => 2,
        opcodes::LDC_W | opcodes::LDC2_W => 3,
        0x15..=0x19 => 2,
        0x1a..=0x35 => 1,
        0x36..=0x3a => 2,
        0x3b..=0x4e => 1,
        0x4f..=0x56 => 1,
        0x57..=0x5f => 1,
        0x60..=0x83 => 1,
        0x84 => 3,
        0x85..=0x98 => 1,
        0x99..=0xa6 => 3,
        opcodes::GOTO | opcodes::JSR => 3,
        0xa9 => 2,
        0xaa => tableswitch_length(code, offset)?,
        0xab => lookupswitch_length(code, offset)?,
        0xac..=0xb1 => 1,
        0xb2..=0xb5 => 3,
        opcodes::INVOKEVIRTUAL | opcodes::INVOKESPECIAL | opcodes::INVOKESTATIC => 3,
        opcodes::INVOKEINTERFACE | opcodes::INVOKEDYNAMIC => 5,
        0xbb => 3,
        0xbc => 2,
        0xbd => 3,
        0xbe | 0xbf => 1,
        0xc0 | 0xc1 => 3,
        0xc2 | 0xc3 => 1,
        0xc4 => wide_length(code, offset)?,
        0xc5 => 4,
        0xc6 | 0xc7 => 3,
        opcodes::GOTO_W | opcodes::JSR_W => 5,
        0xca => 1,
        0xfe | 0xff => 1,
        _ => anyhow::bail!("unsupported opcode 0x{:02x}", opcode),
    };
    Ok(length)
}

fn tableswitch_length(code: &[u8], offset: usize) -> Result<usize> {
    let padding = padding(offset);
    let base = offset + 1 + padding;
    let low = read_i32(code, base + 4)?;
    let high = read_i32(code, base + 8)?;
    let count = high
        .checked_sub(low)
        .and_then(|v| v.checked_add(1))
        .context("invalid tableswitch range")?;
    if count < 0 {
        anyhow::bail!("invalid tableswitch range");
    }
    Ok(1 + padding + 12 + (count as usize) * 4)
}

fn lookupswitch_length(code: &[u8], offset: usize) -> Result<usize> {
    let padding = padding(offset);
    let base = offset + 1 + padding;
    let npairs = read_i32(code, base + 4)?;
    if npairs < 0 {
        anyhow::bail!("invalid lookupswitch pairs");
    }
    Ok(1 + padding + 8 + (npairs as usize) * 8)
}

fn wide_length(code: &[u8], offset: usize) -> Result<usize> {
    let opcode = code
        .get(offset + 1)
        .copied()
        .context("missing wide opcode")?;
    if opcode == 0x84 { Ok(6) } else { Ok(4) }
}

pub(crate) fn padding(offset: usize) -> usize {
    (4 - ((offset + 1) % 4)) % 4
}

pub(crate) fn read_u16(code: &[u8], offset: usize) -> Result<u16> {
    let slice = code
        .get(offset..offset + 2)
        .context("bytecode u16 out of bounds")?;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
}

pub(crate) fn read_u32(code: &[u8], offset: usize) -> Result<u32> {
    let slice = code
        .get(offset..offset + 4)
        .context("bytecode u32 out of bounds")?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_i32(code: &[u8], offset: usize) -> Result<i32> {
    let value = read_u32(code, offset)?;
    Ok(i32::from_be_bytes(value.to_be_bytes()))
}

fn resolve_string_literal(constant_pool: &[ConstantPool], index: u16) -> Result<Option<String>> {
    let entry = constant_pool
        .get(index as usize)
        .context("missing constant pool entry")?;
    match entry {
        ConstantPool::String { string_index } => {
            let value = resolve_utf8(constant_pool, *string_index)?;
            Ok(Some(value))
        }
        ConstantPool::Utf8 { value } => Ok(Some(value.clone())),
        _ => Ok(None),
    }
}

fn parse_exception_handlers(
    table: &[jclassfile::attributes::ExceptionRecord],
    constant_pool: &[ConstantPool],
) -> Result<Vec<ExceptionHandler>> {
    let mut handlers = Vec::new();
    for entry in table {
        let catch_type = if entry.catch_type() == 0 {
            None
        } else {
            Some(
                resolve_class_name(constant_pool, entry.catch_type())
                    .context("resolve catch type")?,
            )
        };
        handlers.push(ExceptionHandler {
            start_pc: entry.start_pc() as u32,
            end_pc: entry.end_pc() as u32,
            handler_pc: entry.handler_pc() as u32,
            catch_type,
        });
    }
    Ok(handlers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::io::Write;
    use std::sync::OnceLock;
    use std::time::{SystemTime, UNIX_EPOCH};
    use zip::ZipArchive;
    use zip::write::SimpleFileOptions;

    #[test]
    fn scan_inputs_rejects_invalid_class_file() {
        let temp_dir = std::env::temp_dir().join(format!(
            "inspequte-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).expect("create temp dir");
        let class_path = temp_dir.join("bad.class");
        fs::write(&class_path, b"nope").expect("write test class");

        let result = scan_inputs(&class_path, &[]);

        assert!(result.is_err());
        fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
    }

    #[test]
    fn scan_inputs_accepts_valid_jar() {
        let jar_path = jspecify_jar_path().expect("download jar");
        let result = scan_inputs(&jar_path, &[]).expect("scan jar");

        assert!(result.class_count > 0);
        assert_eq!(result.artifacts.len(), 1);
        let first_uri = result
            .artifacts
            .first()
            .and_then(|artifact| artifact.location.as_ref())
            .and_then(|location| location.uri.as_ref())
            .cloned()
            .expect("artifact uri");
        assert!(first_uri.ends_with("jspecify-1.0.0.jar"));
    }

    #[test]
    fn scan_inputs_accepts_valid_class_file() {
        let jar_path = jspecify_jar_path().expect("download jar");
        let class_bytes = extract_first_class(&jar_path).expect("extract class");

        let temp_dir = std::env::temp_dir().join(format!(
            "inspequte-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).expect("create temp dir");
        let class_path = temp_dir.join("Sample.class");
        fs::write(&class_path, class_bytes).expect("write class file");

        let result = scan_inputs(&class_path, &[]).expect("scan class");

        assert_eq!(result.class_count, 1);
        assert_eq!(result.artifacts.len(), 1);
        fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
    }

    #[test]
    fn scan_inputs_resolves_manifest_classpath() {
        let temp_dir = std::env::temp_dir().join(format!(
            "inspequte-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).expect("create temp dir");

        let dep_path = temp_dir.join("dep.jar");
        create_manifest_jar(&dep_path, None).expect("create dep jar");
        let jar_path = temp_dir.join("main.jar");
        create_manifest_jar(&jar_path, Some("dep.jar")).expect("create main jar");

        let result = scan_inputs(&jar_path, &[]);

        assert!(result.is_ok());
        fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
    }

    #[test]
    fn scan_inputs_errors_on_missing_manifest_classpath_entry() {
        let temp_dir = std::env::temp_dir().join(format!(
            "inspequte-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).expect("create temp dir");

        let jar_path = temp_dir.join("main.jar");
        create_manifest_jar(&jar_path, Some("missing.jar")).expect("create main jar");

        let result = scan_inputs(&jar_path, &[]);

        assert!(result.is_err());
        fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
    }

    #[test]
    fn default_nullness_parses_marked_and_unmarked() {
        let constant_pool = vec![
            ConstantPool::Utf8 {
                value: String::new(),
            },
            ConstantPool::Utf8 {
                value: "Lorg/jspecify/annotations/NullMarked;".to_string(),
            },
            ConstantPool::Utf8 {
                value: "Lorg/jspecify/annotations/NullUnmarked;".to_string(),
            },
        ];
        let marked = jclassfile::attributes::Annotation::new(1, Vec::new());
        let unmarked = jclassfile::attributes::Annotation::new(2, Vec::new());

        let marked_attr = jclassfile::attributes::Attribute::RuntimeVisibleAnnotations {
            annotations: vec![marked],
            raw: Vec::new(),
        };
        let unmarked_attr = jclassfile::attributes::Attribute::RuntimeVisibleAnnotations {
            annotations: vec![unmarked],
            raw: Vec::new(),
        };

        let marked_default =
            parse_default_nullness(&[marked_attr.clone()], &constant_pool).expect("marked default");
        let unmarked_default =
            parse_default_nullness(&[unmarked_attr], &constant_pool).expect("unmarked default");
        let empty_default = parse_default_nullness(&[], &constant_pool).expect("empty default");

        assert_eq!(marked_default, DefaultNullness::NonNull);
        assert_eq!(unmarked_default, DefaultNullness::Unmarked);
        assert_eq!(empty_default, DefaultNullness::Inherit);
    }

    #[test]
    fn default_nullness_applies_to_reference_types() {
        let constant_pool = vec![ConstantPool::Utf8 {
            value: String::new(),
        }];
        let nullness = parse_method_nullness(
            &constant_pool,
            &[],
            "(Ljava/lang/String;)Ljava/lang/String;",
            DefaultNullness::NonNull,
        )
        .expect("method nullness");

        assert_eq!(nullness.parameter_nullness.len(), 1);
        assert_eq!(nullness.parameter_nullness[0], Nullness::NonNull);
        assert_eq!(nullness.return_nullness, Nullness::NonNull);
    }

    #[test]
    fn nullunmarked_overrides_class_default() {
        let constant_pool = vec![
            ConstantPool::Utf8 {
                value: String::new(),
            },
            ConstantPool::Utf8 {
                value: "Lorg/jspecify/annotations/NullUnmarked;".to_string(),
            },
        ];
        let unmarked = jclassfile::attributes::Annotation::new(1, Vec::new());
        let unmarked_attr = jclassfile::attributes::Attribute::RuntimeVisibleAnnotations {
            annotations: vec![unmarked],
            raw: Vec::new(),
        };
        let nullness = parse_method_nullness(
            &constant_pool,
            &[unmarked_attr],
            "(Ljava/lang/String;)Ljava/lang/String;",
            DefaultNullness::NonNull,
        )
        .expect("method nullness");

        assert_eq!(nullness.parameter_nullness[0], Nullness::Unknown);
        assert_eq!(nullness.return_nullness, Nullness::Unknown);
    }

    fn extract_first_class(jar_path: &Path) -> Result<Vec<u8>> {
        let file =
            fs::File::open(jar_path).with_context(|| format!("open {}", jar_path.display()))?;
        let mut archive =
            ZipArchive::new(file).with_context(|| format!("read {}", jar_path.display()))?;
        for index in 0..archive.len() {
            let mut entry = archive
                .by_index(index)
                .with_context(|| format!("read {}:{}", jar_path.display(), index))?;
            if entry.is_dir()
                || !entry.name().ends_with(".class")
                || entry.name().ends_with("module-info.class")
            {
                continue;
            }
            let mut data = Vec::new();
            entry.read_to_end(&mut data).context("read class bytes")?;
            return Ok(data);
        }

        anyhow::bail!("no class entry found in {}", jar_path.display());
    }

    fn create_manifest_jar(path: &Path, class_path: Option<&str>) -> Result<()> {
        let file = fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
        let mut writer = zip::ZipWriter::new(file);
        let mut manifest = String::from("Manifest-Version: 1.0\n");
        if let Some(class_path) = class_path {
            manifest.push_str(&format!("Class-Path: {class_path}\n"));
        }
        manifest.push('\n');
        writer
            .start_file("META-INF/MANIFEST.MF", SimpleFileOptions::default())
            .context("start manifest entry")?;
        writer
            .write_all(manifest.as_bytes())
            .context("write manifest")?;
        writer.finish().context("finish jar")?;
        Ok(())
    }

    fn jspecify_jar_path() -> Result<PathBuf> {
        static JAR_PATH: OnceLock<PathBuf> = OnceLock::new();
        if let Some(path) = JAR_PATH.get() {
            return Ok(path.clone());
        }
        let jar_path = download_jspecify_jar()?;
        let _ = JAR_PATH.set(jar_path.clone());
        Ok(jar_path)
    }

    fn download_jspecify_jar() -> Result<PathBuf> {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-fixtures");
        fs::create_dir_all(&dir).context("create fixture directory")?;
        let jar_path = dir.join("jspecify-1.0.0.jar");
        if jar_path.exists() {
            return Ok(jar_path);
        }

        let url =
            "https://repo.maven.apache.org/maven2/org/jspecify/jspecify/1.0.0/jspecify-1.0.0.jar";
        let mut response = ureq::get(url).call().context("download jspecify jar")?;
        if response.status().as_u16() >= 400 {
            anyhow::bail!(
                "failed to download jspecify jar: HTTP {}",
                response.status()
            );
        }

        let mut reader = response.body_mut().as_reader();
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .context("read jspecify jar")?;
        fs::write(&jar_path, bytes).context("write jspecify jar")?;

        Ok(jar_path)
    }
}
