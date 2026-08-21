# Contributing to Cover

Thank you for your interest in contributing! This project is open source and
welcomes bug reports, feature requests, documentation improvements, and code
changes.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating, you agree to uphold it.

## Ways to Contribute

- **Report bugs** — open an issue with steps to reproduce, expected vs. actual
  behavior, and your environment (OS, Go version, config if relevant).
- **Suggest features** — describe the problem you are trying to solve and why
  existing behavior is not enough.
- **Improve docs** — fix typos, clarify setup steps, or add examples.
- **Submit code** — fix bugs, add detectors, improve performance, or extend
  tests.

## Development Setup

1. Fork the repository and clone your fork:

   ```sh
   git clone https://github.com/<your-username>/cover.git
   cd cover
   ```

2. Build the binary:

   ```sh
   go build -o cover ./cmd/cover
   ```

3. Run the test suite:

   ```sh
   go test -race -count=1 ./...
   ```

   CI runs the same command on every push and pull request (see
   `.github/workflows/ci.yml`).

4. Try your changes locally:

   ```sh
   ./cover test          # offline redaction smoke test
   ./cover init          # create a local config (optional)
   ./cover start         # run the proxy (optional)
   ```

## Pull Request Guidelines

1. Create a feature branch from `main`:

   ```sh
   git checkout -b my-change
   ```

2. Keep changes focused — one logical change per pull request when possible.

3. Add or update tests for behavior you change. Run `go test ./...` before
   opening the PR.

4. Update documentation if you change user-facing behavior, config options, or
   CLI commands.

5. Open a pull request against `main` with:
   - A clear summary of what changed and why
   - A link to any related issue (e.g. `Fixes #123`)
   - Notes on how you tested the change

6. Ensure CI passes. Maintainers may request changes before merging.

## Project Layout

| Path | Purpose |
|------|---------|
| `cmd/cover/` | CLI entrypoint and subcommands |
| `internal/proxy/` | HTTP reverse proxy |
| `internal/redact/` | Redaction engine and placeholder mapping |
| `internal/redact/detectors/` | Regex and custom pattern detectors |
| `internal/llamacpp/` | Optional local LLM fallback detector |
| `internal/config/` | Config loading and validation |
| `configs/` | Example configuration |

## Adding a New Secret Detector

Most structured secrets are detected via regex patterns in
`internal/redact/detectors/regex.go`. To add a new pattern:

1. Add the regex and category name in `regex.go`.
2. Add test cases in `internal/redact/detectors/regex_test.go`.
3. Run `go test ./internal/redact/...` to verify.

For organization-specific patterns, users can also add entries under
`detectors.regex.custom_patterns` in the config file — no code change required.

## Security Issues

Please **do not** open public issues for security vulnerabilities. See
[SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the
[Apache License 2.0](LICENSE).
