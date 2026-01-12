mod scan;

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::json;
use serde_sarif::sarif::{Artifact, Invocation, Run, Sarif, Tool, ToolComponent, SCHEMA_URL};

use crate::scan::scan_inputs;

/// CLI arguments for rtro execution.
#[derive(Parser, Debug)]
#[command(
    name = "rtro",
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
    let scan = scan_inputs(&cli.input, &cli.classpath)?;
    let artifact_count = scan.artifacts.len();
    let invocation = build_invocation();
    let sarif = build_sarif(scan.artifacts, invocation);

    let mut writer = output_writer(cli.output.as_deref())?;
    serde_json::to_writer_pretty(&mut writer, &sarif)
        .context("failed to serialize SARIF output")?;
    writer
        .write_all(b"\n")
        .context("failed to write SARIF output")?;

    if cli.timing && !cli.quiet {
        eprintln!(
            "timing: total_ms={} classes={} artifacts={}",
            started_at.elapsed().as_millis(),
            scan.class_count,
            artifact_count
        );
    }

    Ok(())
}

fn output_writer(output: Option<&Path>) -> Result<Box<dyn Write>> {
    match output {
        Some(path) if path == Path::new("-") => Ok(Box::new(io::stdout())),
        Some(path) => Ok(Box::new(
            File::create(path).with_context(|| format!("failed to open {}", path.display()))?,
        )),
        None => Ok(Box::new(io::stdout())),
    }
}

fn build_invocation() -> Invocation {
    let arguments: Vec<String> = std::env::args().collect();
    let command_line = arguments.join(" ");

    Invocation::builder()
        .execution_successful(true)
        .arguments(arguments)
        .command_line(command_line)
        .build()
}

fn build_sarif(artifacts: Vec<Artifact>, invocation: Invocation) -> Sarif {
    let driver = ToolComponent::builder()
        .name("rustrospective")
        .information_uri("https://github.com/KengoTODA/rustrospective")
        .build();
    let tool = Tool {
        driver,
        extensions: None,
        properties: None,
    };
    let run = if artifacts.is_empty() {
        Run::builder()
            .tool(tool)
            .invocations(vec![invocation])
            .results(Vec::new())
            .build()
    } else {
        Run::builder()
            .tool(tool)
            .invocations(vec![invocation])
            .results(Vec::new())
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

    #[test]
    fn sarif_is_minimal_and_valid_shape() {
        let invocation = Invocation::builder()
            .execution_successful(true)
            .arguments(Vec::<String>::new())
            .build();
        let sarif = build_sarif(Vec::new(), invocation);
        let value = serde_json::to_value(&sarif).expect("serialize SARIF");

        assert_eq!(value["version"], "2.1.0");
        assert_eq!(value["$schema"], SCHEMA_URL);
        assert_eq!(value["runs"][0]["tool"]["driver"]["name"], "rustrospective");
        assert_eq!(
            value["runs"][0]["tool"]["driver"]["informationUri"],
            "https://github.com/KengoTODA/rustrospective"
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
}
