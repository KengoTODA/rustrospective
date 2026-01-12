# AGENTS

## Project context
- Repo: rustrospective (CLI command: `rtro`).
- Purpose: fast, CLI-first static analysis for JVM class/JAR files.
- Output: SARIF v2.1.0 only.
- License: AGPL-3.0.
- Commit style: Conventional Commits v1.0.0.

## Decisions
- `rtro` is the CLI command name.
- Keep `--timing` option in Milestone 1.
- Do not document multithreading for now.
- Add documentation comments to each struct.

## Planned analyses (pre-1.0)
- Dead code: unreachable methods/classes, unused private methods/fields.
- Nullness checks guided by JSpecify annotations.
- Empty catch blocks.
- Insecure API usage: `Runtime.exec`, `ProcessBuilder`, reflective sinks.
- Ineffective equals/hashCode.

## Current scaffold
- `README.md` includes goals, planned analyses, CLI usage, SARIF example, and CI snippet.
- `CONTRIBUTING.md` covers Conventional Commits and AGPL contribution terms.
- `MILESTONES.md` tracks milestones.
- `Cargo.toml` declares the crate and `rtro` binary.
- `.github/workflows/ci.yml` builds, tests, and uploads release artifacts.

## Next focus (Milestone 1)
- Implement CLI skeleton.
- Emit SARIF using `serde-sarif`.
- Deterministic output ordering.
