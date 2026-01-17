# inspequte

[![CI](https://github.com/KengoTODA/inspequte/actions/workflows/ci.yml/badge.svg)](https://github.com/KengoTODA/inspequte/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/inspequte.svg)](https://crates.io/crates/inspequte)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0.en.html)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-yellow.svg)](https://www.conventionalcommits.org/en/v1.0.0/)

> [!WARNING]
> **Experimental / Proof-of-Concept Project**
>
> This repository is intended **for experimental and evaluation purposes only**.
> It is **not designed, reviewed, or supported for production use**.
>
> Do **NOT** use this code in production environments.

inspequte is a fast, CLI-first static analysis tool for JVM class and JAR files.
It focuses on CI/CD speed, deterministic output, and SARIF-only reporting for global
standard compatibility.

The name combines "inspect" and "qute". The CLI command is `inspequte`.

## Goals
- Fast startup and analysis for CI pipelines.
- No IDE or build-tool integration required.
- Deterministic SARIF v2.1.0 output for LLM-friendly automation.

## Planned analyses (pre-1.0)
- Dead code: unreachable methods/classes, unused private methods/fields.
- Nullness issues guided by JSpecify annotations.
- Empty catch blocks.
- Insecure API usage: `Runtime.exec`, `ProcessBuilder`, reflective sinks.
- Ineffective equals/hashCode.

## Bytecode/JDK compatibility
- Supports JVM class files up to Java 21 (major version 65).
- Requires a Java 21 toolchain when compiling test harness sources via `JAVA_HOME`.
- Some advanced bytecode attributes may still be skipped in future releases.

## CLI usage
```
inspequte --input app.jar --classpath lib/ --output results.sarif
```

## Environment variables
- `INSPEQUTE_VALIDATE_SARIF=1` validates SARIF output against the bundled schema (dev only).

## Benchmarks
- `scripts/bench-classpath.sh <input> [repeat] [classpath...]` captures timing baselines for a single input.
- `scripts/bench-spotbugs.sh [repeat]` benchmarks SpotBugs libraries (downloads if needed).

## SARIF output (example)
```json
{
  "version": "2.1.0",
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "inspequte",
          "informationUri": "https://github.com/KengoTODA/inspequte"
        }
      },
      "results": []
    }
  ]
}
```

## CI integration (GitHub Actions)
```yaml
- name: Run inspequte
  run: |
    cargo run --release -- \
      --input app.jar \
      --classpath lib/ \
      --output results.sarif
```

### Upload SARIF to GitHub Code Scanning
```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Validate SARIF during CI (optional)
```yaml
- name: Run inspequte with schema validation
  run: |
    INSPEQUTE_VALIDATE_SARIF=1 cargo run --release -- \
      --input app.jar \
      --classpath lib/ \
      --output results.sarif
```

## License
AGPL-3.0. See `LICENSE`.

## Contributing
Please follow Conventional Commits 1.0.0. See `CONTRIBUTING.md`.
