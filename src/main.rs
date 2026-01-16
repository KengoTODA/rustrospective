mod callgraph;
mod cfg;
mod classpath;
mod descriptor;
mod engine;
mod ir;
mod opcodes;
mod rules;
mod scan;
#[cfg(test)]
mod test_harness;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::json;
use serde_sarif::sarif::{
    Artifact, Invocation, PropertyBag, Run, Sarif, Tool, ToolComponent, SCHEMA_URL,
};

use crate::classpath::resolve_classpath;
use crate::engine::{build_context, Engine};
use crate::scan::scan_inputs;

/// CLI arguments for inspequte execution.
#[derive(Parser, Debug)]
#[command(
    name = "inspequte",
    about = "Fast, deterministic SARIF output for JVM class files and JAR files analysis.",
    version
)]
struct Cli {
    #[arg(long, value_name = "PATH")]
    input: PathBuf,
    #[arg(long, value_name = "PATH")]
    classpath: Vec<PathBuf>,
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
    #[arg(long)]
    quiet: bool,
    #[arg(long)]
    timing: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    run(cli)
}

fn run(cli: Cli) -> Result<()> {
    if !cli.input.exists() {
        anyhow::bail!("input not found: {}", cli.input.display());
    }
    for entry in &cli.classpath {
        if !entry.exists() {
            anyhow::bail!("classpath entry not found: {}", entry.display());
        }
    }

    let started_at = Instant::now();
    let scan_started_at = Instant::now();
    let scan = scan_inputs(&cli.input, &cli.classpath)?;
    let scan_duration_ms = scan_started_at.elapsed().as_millis();
    let artifact_count = scan.artifacts.len();
    let classpath_index = resolve_classpath(&scan.classes)?;
    let classpath_class_count = classpath_index.classes.len();
    let artifacts = scan.artifacts;
    let context = build_context(scan.classes.clone(), classpath_index, &artifacts);
    let engine = Engine::new();
    let analysis = engine.analyze(context)?;
    let invocation_stats = InvocationStats {
        scan_duration_ms,
        class_count: scan.class_count,
        artifact_count,
        classpath_class_count,
    };
    let invocation = build_invocation(&invocation_stats);
    let sarif = build_sarif(artifacts, invocation, analysis.rules, analysis.results);

    let write_started_at = Instant::now();
    let mut writer = output_writer(cli.output.as_deref())?;
    serde_json::to_writer_pretty(&mut writer, &sarif)
        .context("failed to serialize SARIF output")?;
    writer
        .write_all(b"\n")
        .context("failed to write SARIF output")?;
    let write_duration_ms = write_started_at.elapsed().as_millis();
    
    if cli.timing && !cli.quiet {
        eprintln!(
            "timing: total_ms={} scan_ms={} write_ms={} (classes={} artifacts={})",
            started_at.elapsed().as_millis(),
            scan_duration_ms,
            write_duration_ms,
            scan.class_count,
            artifact_count
        );
    }

    Ok(())
}

fn output_writer(output: Option<&Path>) -> Result<Box<dyn Write>> {
    match output {
        Some(path) if path == Path::new("-") => Ok(Box::new(io::stdout())),
        Some(path) => {
            Ok(Box::new(File::create(path).with_context(|| {
                format!("failed to open {}", path.display())
            })?))
        }
        None => Ok(Box::new(io::stdout())),
    }
}

/// Metadata captured for SARIF invocation properties.
struct InvocationStats {
    scan_duration_ms: u128,
    class_count: usize,
    artifact_count: usize,
    classpath_class_count: usize,
}

fn build_invocation(stats: &InvocationStats) -> Invocation {
    let arguments: Vec<String> = std::env::args().collect();
    let command_line = arguments.join(" ");
    let mut properties = BTreeMap::new();
    properties.insert("inspequte.scan_ms".to_string(), json!(stats.scan_duration_ms));
    properties.insert("inspequte.class_count".to_string(), json!(stats.class_count));
    properties.insert(
        "inspequte.artifact_count".to_string(),
        json!(stats.artifact_count),
    );
    properties.insert(
        "inspequte.classpath_class_count".to_string(),
        json!(stats.classpath_class_count),
    );

    Invocation::builder()
        .execution_successful(true)
        .arguments(arguments)
        .command_line(command_line)
        .properties(
            PropertyBag::builder()
                .additional_properties(properties)
                .build(),
        )
        .build()
}

fn build_sarif(
    artifacts: Vec<Artifact>,
    invocation: Invocation,
    rules: Vec<serde_sarif::sarif::ReportingDescriptor>,
    results: Vec<serde_sarif::sarif::Result>,
) -> Sarif {
    let driver = if rules.is_empty() {
        ToolComponent::builder()
            .name("inspequte")
            .information_uri("https://github.com/KengoTODA/inspequte")
            .build()
    } else {
        ToolComponent::builder()
            .name("inspequte")
            .information_uri("https://github.com/KengoTODA/inspequte")
            .rules(rules)
            .build()
    };
    let tool = Tool {
        driver,
        extensions: None,
        properties: None,
    };
    let run = if artifacts.is_empty() {
        Run::builder()
            .tool(tool)
            .invocations(vec![invocation])
            .results(results)
            .build()
    } else {
        Run::builder()
            .tool(tool)
            .invocations(vec![invocation])
            .results(results)
            .artifacts(artifacts)
            .build()
    };

    Sarif::builder()
        .schema(SCHEMA_URL)
        .runs(vec![run])
        .version(json!("2.1.0"))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::classpath::resolve_classpath;
    use crate::engine::{build_context, Engine};
    use crate::scan::scan_inputs;

    #[test]
    fn sarif_is_minimal_and_valid_shape() {
        let invocation = build_invocation(&InvocationStats {
            scan_duration_ms: 0,
            class_count: 0,
            artifact_count: 0,
            classpath_class_count: 0,
        });
        let sarif = build_sarif(Vec::new(), invocation, Vec::new(), Vec::new());
        let value = serde_json::to_value(&sarif).expect("serialize SARIF");

        assert_eq!(value["version"], "2.1.0");
        assert_eq!(value["$schema"], SCHEMA_URL);
        assert_eq!(value["runs"][0]["tool"]["driver"]["name"], "inspequte");
        assert_eq!(
            value["runs"][0]["tool"]["driver"]["informationUri"],
            "https://github.com/KengoTODA/inspequte"
        );
        assert!(value["runs"][0]["results"]
            .as_array()
            .expect("results array")
            .is_empty());
        assert_eq!(
            value["runs"][0]["invocations"][0]["executionSuccessful"],
            true
        );
    }

    #[test]
    fn sarif_callgraph_snapshot() {
        let temp_dir = std::env::temp_dir().join(format!(
            "inspequte-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).expect("create temp dir");

        let class_a = build_class_a();
        let class_b = build_class_b();
        fs::write(temp_dir.join("A.class"), class_a).expect("write A.class");
        fs::write(temp_dir.join("B.class"), class_b).expect("write B.class");

        let scan = scan_inputs(&temp_dir, &[]).expect("scan classes");
        let classpath = resolve_classpath(&scan.classes).expect("resolve classpath");
        let artifacts = scan.artifacts.clone();
        let context = build_context(scan.classes.clone(), classpath, &artifacts);
        let engine = Engine::new();
        let analysis = engine.analyze(context).expect("analysis");
        let invocation = Invocation::builder()
            .execution_successful(true)
            .arguments(Vec::<String>::new())
            .build();
        let artifacts = normalize_artifacts(artifacts);
        let sarif = build_sarif(artifacts, invocation, analysis.rules, analysis.results);
        let actual = serde_json::to_string_pretty(&sarif).expect("serialize SARIF");
        let snapshot_path = snapshot_path("callgraph.sarif");

        if std::env::var("INSPEQUTE_UPDATE_SNAPSHOTS").is_ok() {
            fs::create_dir_all(snapshot_path.parent().expect("snapshot parent"))
                .expect("create snapshot dir");
            let mut file = fs::File::create(&snapshot_path).expect("create snapshot");
            file.write_all(actual.as_bytes()).expect("write snapshot");
            file.write_all(b"\n").expect("write snapshot newline");
        }

        let expected = fs::read_to_string(&snapshot_path).expect("read snapshot");
        assert_eq!(actual.trim_end(), expected.trim_end());

        fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
    }

    fn snapshot_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("snapshots")
            .join(name)
    }

    fn build_class_a() -> Vec<u8> {
        let mut builder = ClassFileBuilder::new("A", "java/lang/Object");
        let object_init = builder.add_method_ref("java/lang/Object", "<init>", "()V");
        let b_class = builder.add_class("B");
        let b_init = builder.add_method_ref("B", "<init>", "()V");
        let b_bar = builder.add_method_ref("B", "bar", "()V");

        let init_code = vec![0x2a, 0xb7, high(object_init), low(object_init), 0xb1];
        builder.add_method("<init>", "()V", init_code, 1, 1);

        let foo_code = vec![
            0xbb,
            high(b_class),
            low(b_class),
            0x59,
            0xb7,
            high(b_init),
            low(b_init),
            0xb6,
            high(b_bar),
            low(b_bar),
            0xb1,
        ];
        builder.add_method("foo", "()V", foo_code, 2, 1);

        builder.finish()
    }

    fn build_class_b() -> Vec<u8> {
        let mut builder = ClassFileBuilder::new("B", "java/lang/Object");
        let object_init = builder.add_method_ref("java/lang/Object", "<init>", "()V");
        let init_code = vec![0x2a, 0xb7, high(object_init), low(object_init), 0xb1];
        builder.add_method("<init>", "()V", init_code, 1, 1);
        let bar_code = vec![0xb1];
        builder.add_method("bar", "()V", bar_code, 0, 1);
        builder.finish()
    }

    /// Minimal class file writer for snapshot testing.
    struct ClassFileBuilder {
        cp: Vec<CpEntry>,
        this_class: u16,
        super_class: u16,
        methods: Vec<MethodSpec>,
        code_index: u16,
    }

    impl ClassFileBuilder {
        fn new(class_name: &str, super_name: &str) -> Self {
            let mut builder = Self {
                cp: Vec::new(),
                this_class: 0,
                super_class: 0,
                methods: Vec::new(),
                code_index: 0,
            };
            builder.code_index = builder.add_utf8("Code");
            builder.this_class = builder.add_class(class_name);
            builder.super_class = builder.add_class(super_name);
            builder
        }

        fn add_utf8(&mut self, value: &str) -> u16 {
            self.cp.push(CpEntry::Utf8(value.to_string()));
            self.cp.len() as u16
        }

        fn add_class(&mut self, name: &str) -> u16 {
            let name_index = self.add_utf8(name);
            self.cp.push(CpEntry::Class(name_index));
            self.cp.len() as u16
        }

        fn add_name_and_type(&mut self, name: &str, descriptor: &str) -> u16 {
            let name_index = self.add_utf8(name);
            let descriptor_index = self.add_utf8(descriptor);
            self.cp
                .push(CpEntry::NameAndType(name_index, descriptor_index));
            self.cp.len() as u16
        }

        fn add_method_ref(&mut self, class: &str, name: &str, descriptor: &str) -> u16 {
            let class_index = self.add_class(class);
            let name_and_type = self.add_name_and_type(name, descriptor);
            self.cp.push(CpEntry::MethodRef(class_index, name_and_type));
            self.cp.len() as u16
        }

        fn add_method(
            &mut self,
            name: &str,
            descriptor: &str,
            code: Vec<u8>,
            max_stack: u16,
            max_locals: u16,
        ) {
            let name_index = self.add_utf8(name);
            let descriptor_index = self.add_utf8(descriptor);
            self.methods.push(MethodSpec {
                name_index,
                descriptor_index,
                code,
                max_stack,
                max_locals,
            });
        }

        fn finish(self) -> Vec<u8> {
            let mut bytes = Vec::new();
            write_u32(&mut bytes, 0xCAFEBABE);
            write_u16(&mut bytes, 0);
            write_u16(&mut bytes, 52);
            write_u16(&mut bytes, (self.cp.len() + 1) as u16);
            for entry in &self.cp {
                entry.write(&mut bytes);
            }
            write_u16(&mut bytes, 0x0021);
            write_u16(&mut bytes, self.this_class);
            write_u16(&mut bytes, self.super_class);
            write_u16(&mut bytes, 0);
            write_u16(&mut bytes, 0);
            write_u16(&mut bytes, self.methods.len() as u16);
            for method in &self.methods {
                write_u16(&mut bytes, 0x0001);
                write_u16(&mut bytes, method.name_index);
                write_u16(&mut bytes, method.descriptor_index);
                write_u16(&mut bytes, 1);
                write_u16(&mut bytes, self.code_index);
                let attr_len = 12 + method.code.len() as u32;
                write_u32(&mut bytes, attr_len);
                write_u16(&mut bytes, method.max_stack);
                write_u16(&mut bytes, method.max_locals);
                write_u32(&mut bytes, method.code.len() as u32);
                bytes.extend_from_slice(&method.code);
                write_u16(&mut bytes, 0);
                write_u16(&mut bytes, 0);
            }
            write_u16(&mut bytes, 0);
            bytes
        }
    }

    /// Method definition for generated class files.
    struct MethodSpec {
        name_index: u16,
        descriptor_index: u16,
        code: Vec<u8>,
        max_stack: u16,
        max_locals: u16,
    }

    /// Constant pool entries needed by snapshot class files.
    enum CpEntry {
        Utf8(String),
        Class(u16),
        NameAndType(u16, u16),
        MethodRef(u16, u16),
    }

    impl CpEntry {
        fn write(&self, bytes: &mut Vec<u8>) {
            match self {
                CpEntry::Utf8(value) => {
                    bytes.push(1);
                    write_u16(bytes, value.len() as u16);
                    bytes.extend_from_slice(value.as_bytes());
                }
                CpEntry::Class(name_index) => {
                    bytes.push(7);
                    write_u16(bytes, *name_index);
                }
                CpEntry::NameAndType(name_index, descriptor_index) => {
                    bytes.push(12);
                    write_u16(bytes, *name_index);
                    write_u16(bytes, *descriptor_index);
                }
                CpEntry::MethodRef(class_index, name_and_type) => {
                    bytes.push(10);
                    write_u16(bytes, *class_index);
                    write_u16(bytes, *name_and_type);
                }
            }
        }
    }

    fn write_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn write_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn high(value: u16) -> u8 {
        (value >> 8) as u8
    }

    fn low(value: u16) -> u8 {
        (value & 0xff) as u8
    }

    fn normalize_artifacts(
        artifacts: Vec<serde_sarif::sarif::Artifact>,
    ) -> Vec<serde_sarif::sarif::Artifact> {
        artifacts
            .into_iter()
            .map(|mut artifact| {
                if let Some(location) = artifact.location.as_mut() {
                    if let Some(uri) = &location.uri {
                        if let Some(name) = artifact_basename(uri) {
                            location.uri = Some(name);
                        }
                    }
                }
                artifact
            })
            .collect()
    }

    fn artifact_basename(uri: &str) -> Option<String> {
        if let Some(rest) = uri.strip_prefix("jar:") {
            let entry = rest.split("!/").nth(1)?;
            return Some(
                PathBuf::from(entry)
                    .file_name()?
                    .to_string_lossy()
                    .to_string(),
            );
        }
        if let Some(rest) = uri.strip_prefix("file://") {
            return Some(
                PathBuf::from(rest)
                    .file_name()?
                    .to_string_lossy()
                    .to_string(),
            );
        }
        PathBuf::from(uri)
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
    }
}
