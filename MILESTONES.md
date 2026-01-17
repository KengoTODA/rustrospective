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
- [x] Implement JAR/class loading and classpath resolution.
- [x] Parse class files via `jclassfile`.
- [x] Validate missing or duplicate classes.
- [x] Add timing/profiling for parsing.

## Milestone 3 - IR + Call Graph Prototype
- [x] Define lean IR for methods, bytecode instructions, and basic blocks.
- [x] Build call graph with CHA baseline.
- [x] Emit SARIF code flows for call paths.
- [x] Add fixtures and golden SARIF snapshots.

## Milestone 4 - CFG + Rule Engine
- [x] Build CFG per method.
- [x] Implement configurable rule engine.
- [x] Add initial rule set: Dead code.
- [x] Add initial rule set: JSpecify-based nullness checks.
- [x] Add initial rule set: Empty catch blocks.
- [x] Add initial rule set: Insecure API usage sinks.
- [x] Add initial rule set: Ineffective equals/hashCode.

## Milestone 5 - CI Hardened Release
- [x] Stable output ordering and exit codes.
- [x] Optional SARIF schema validation.
- [ ] Caching for classpath resolution.
    - Skip this because performance is not improved according to the benchmark
- [x] Benchmarks and performance baselines.
- [x] CI integration examples.

## Milestone 6 - 1.0 Release
- Tag `v1.0.0` with release notes.
- Publish usage examples and SARIF viewer guidance.
- [x] Document bytecode/JDK compatibility.
- [x] Setup `release-please` to publish changes to GitHub Releases that enables release immutability.
