use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use jclassfile::class_file;
use serde_json::Value;
use serde_sarif::sarif::{Artifact, ArtifactLocation, ArtifactRoles};
use zip::ZipArchive;

/// Snapshot of parsed artifacts and class counts for a scan.
pub(crate) struct ScanOutput {
    pub(crate) artifacts: Vec<Artifact>,
    pub(crate) class_count: usize,
}

pub(crate) fn scan_inputs(input: &Path, classpath: &[PathBuf]) -> Result<ScanOutput> {
    let mut artifacts = Vec::new();
    let mut class_count = 0;

    scan_path(input, true, true, &mut artifacts, &mut class_count)?;

    // Keep deterministic ordering by sorting classpath entries and directory listings.
    let mut classpath_entries = classpath.to_vec();
    classpath_entries.sort_by(|a, b| path_key(a).cmp(&path_key(b)));

    for entry in classpath_entries {
        scan_path(&entry, false, true, &mut artifacts, &mut class_count)?;
    }

    Ok(ScanOutput {
        artifacts,
        class_count,
    })
}

fn scan_path(
    path: &Path,
    is_input: bool,
    strict: bool,
    artifacts: &mut Vec<Artifact>,
    class_count: &mut usize,
) -> Result<()> {
    if path.is_dir() {
        scan_dir(path, artifacts, class_count)?;
        return Ok(());
    }

    let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    let roles = if is_input {
        Some(vec![serde_json::to_value(ArtifactRoles::AnalysisTarget)
            .expect("serialize artifact role")])
    } else {
        None
    };

    match extension {
        "class" => scan_class_file(path, roles, artifacts, class_count),
        "jar" => scan_jar_file(path, roles, artifacts, class_count),
        _ => {
            if strict {
                anyhow::bail!("unsupported input file: {}", path.display())
            } else {
                Ok(())
            }
        }
    }
}

fn scan_dir(path: &Path, artifacts: &mut Vec<Artifact>, class_count: &mut usize) -> Result<()> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(path)
        .with_context(|| format!("failed to read directory {}", path.display()))?
    {
        let entry = entry.with_context(|| format!("failed to read entry under {}", path.display()))?;
        entries.push(entry.path());
    }

    entries.sort_by(|a, b| path_key(a).cmp(&path_key(b)));

    for entry in entries {
        if entry.is_dir() {
            scan_dir(&entry, artifacts, class_count)?;
        } else {
            scan_path(&entry, false, false, artifacts, class_count)?;
        }
    }

    Ok(())
}

fn scan_class_file(
    path: &Path,
    roles: Option<Vec<Value>>,
    artifacts: &mut Vec<Artifact>,
    class_count: &mut usize,
) -> Result<()> {
    let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    class_file::parse(&data).with_context(|| format!("failed to parse {}", path.display()))?;
    *class_count += 1;

    push_path_artifact(path, roles, data.len() as u64, None, artifacts)?;
    Ok(())
}

fn scan_jar_file(
    path: &Path,
    roles: Option<Vec<Value>>,
    artifacts: &mut Vec<Artifact>,
    class_count: &mut usize,
) -> Result<()> {
    let file = fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
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
        if name.ends_with(".class") && !name.ends_with("module-info.class") {
            entry_names.push(name);
        }
    }

    entry_names.sort();

    for name in entry_names {
        let mut entry = archive
            .by_name(&name)
            .with_context(|| format!("failed to read {}:{}", path.display(), name))?;
        let mut data = Vec::new();
        entry
            .read_to_end(&mut data)
            .with_context(|| format!("failed to read {}:{}", path.display(), name))?;
        class_file::parse(&data)
            .with_context(|| format!("failed to parse {}:{}", path.display(), name))?;
        *class_count += 1;

        let entry_uri = jar_entry_uri(path, &name);
        push_artifact(entry_uri, entry.size(), Some(jar_index), None, artifacts);
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
    path.to_string_lossy().to_string()
}

fn jar_entry_uri(jar_path: &Path, entry_name: &str) -> String {
    format!("jar:{}!/{}", jar_path.to_string_lossy(), entry_name)
}

fn path_key(path: &Path) -> String {
    path.to_string_lossy().to_string()
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::sync::OnceLock;
    use std::time::{SystemTime, UNIX_EPOCH};
    use zip::ZipArchive;

    #[test]
    fn scan_inputs_rejects_invalid_class_file() {
        let temp_dir = std::env::temp_dir().join(format!(
            "rtro-test-{}",
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
        assert!(!result.artifacts.is_empty());
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
            "rtro-test-{}",
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

        let url = "https://repo.maven.apache.org/maven2/org/jspecify/jspecify/1.0.0/jspecify-1.0.0.jar";
        let response = ureq::get(url)
            .call()
            .context("download jspecify jar")?;
        if response.status() >= 400 {
            anyhow::bail!("failed to download jspecify jar: HTTP {}", response.status());
        }

        let mut reader = response.into_reader();
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .context("read jspecify jar")?;
        fs::write(&jar_path, bytes).context("write jspecify jar")?;

        Ok(jar_path)
    }
}
