# Contributing

Thanks for your interest in inspequte.

## Commit messages
We follow Conventional Commits 1.0.0. Examples:
- `feat(cli): add sarif output`
- `fix(parser): handle invalid constant pool`
- `docs: update README`

## Development
- Run `cargo build` for a debug build.
- Run `cargo test` before submitting changes.

### Environment variables
- `INSPEQUTE_VALIDATE_SARIF=1` validates SARIF output against the bundled schema (dev only).

### Benchmarks
- `scripts/bench-classpath.sh <input> [repeat] [classpath...]` captures timing baselines for a single input.
- `scripts/bench-spotbugs.sh [repeat]` benchmarks SpotBugs libraries (downloads if needed).

## License
By contributing, you agree that your contributions will be licensed under AGPL-3.0.
