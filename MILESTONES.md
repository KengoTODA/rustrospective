# Milestones

## Milestone 0 - Project Scaffold
- [x] Add AGPL-3.0 `LICENSE`.
- [x] Create `README.md` with goals and SARIF-only stance.
- [x] Add badges for CI, AGPL-3.0, and Conventional Commits 1.0.0.
- [x] Add `CONTRIBUTING.md` with commit conventions.
- [x] Add a basic GitHub Actions workflow for build/test/artifacts.
- [x] Add minimal, buildable Rust crate skeleton.

## Milestone 1 - CLI Skeleton + SARIF Output
- [x] Implement CLI entrypoint with input/output options.
- [x] Emit valid SARIF v2.1.0 using `serde-sarif`.
- [x] Add deterministic output ordering.
- [x] Add `--version`, `--help`, `--quiet`, `--timing`.

## Milestone 2 - Parsing + Classpath Resolution
- Implement JAR/class loading and classpath resolution.
- Parse class files via `jclassfile`.
- Validate missing or duplicate classes.
- Add timing/profiling for parsing.

## Milestone 3 - IR + Call Graph Prototype
- Define lean IR for methods, bytecode instructions, and basic blocks.
- Build call graph with CHA baseline.
- Emit SARIF code flows for call paths.
- Add fixtures and golden SARIF snapshots.

## Milestone 4 - CFG + Rule Engine
- Build CFG per method.
- Implement configurable rule engine.
- Add initial rule set:
  - Dead code.
  - JSpecify-based nullness checks.
  - Empty catch blocks.
  - Insecure API usage sinks.
  - Hardcoded credentials heuristics.
  - Ineffective equals/hashCode.

## Milestone 5 - CI Hardened Release
- Stable output ordering and exit codes.
- Optional SARIF schema validation.
- Caching for classpath resolution.
- Benchmarks and performance baselines.
- CI integration examples.

## Milestone 6 - 1.0 Release
- Tag `v1.0.0` with release notes.
- Publish usage examples and SARIF viewer guidance.
- Document bytecode/JDK compatibility.
- Setup `release-please` to publish changes to GitHub Releases that enables release immutability.
