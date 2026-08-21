# Cover

[![CI](https://github.com/DavidCarliez/cover/actions/workflows/ci.yml/badge.svg)](https://github.com/DavidCarliez/cover/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Cover sensitive data before it reaches an AI provider.**

Cover is a local privacy proxy for Codex, Claude Code, Cursor, OpenAI-compatible
clients, and other HTTP-based agents. It finds secrets and personal data in
outgoing JSON, replaces them with safe stand-ins, and restores the originals in
the response so the agent continues to work normally.

Cover is a privacy-focused fork of
[densub/llm-guard](https://github.com/densub/llm-guard). It retains the
upstream project's Apache 2.0 license and attribution while extending it with
policy-driven replacement, fail-closed handling, session isolation, inspection,
and Codex/OMP support.

## Features

- Built-in detection for major API keys, tokens, private keys, JWTs, passwords,
  emails, phone numbers, SSNs, credit cards, and IBANs.
- Declarative rules with `allow`, `placeholder`, `pseudonymize`, `mask`,
  `redact`, and `block` actions.
- Realistic replacement generators for emails, usernames, passwords, IP
  addresses, hosts, domains, UUIDs, URLs, aliases, and other structured values.
- Bounded, session-isolated, in-memory mappings that keep replacements stable
  and restore originals without writing the mapping to disk.
- Transparent restoration for JSON responses and streaming SSE responses.
- Fail-closed handling for malformed JSON, compressed bodies, invalid policy,
  mapping exhaustion, detector failure, and explicit block rules.
- `cover inspect` for previewing the exact protected JSON without sending it.
- `cover doctor` for local policy, daemon, key, listener, and Codex routing checks.
- `cover monitor` for a live, allowlisted metadata view with no prompt content.
- Safe metadata-only audit logs with no raw prompt or response bodies.
- Configurable image policy (`allow`, `warn`, or `block`).
- Optional local llama.cpp detector for sensitive free-form text that regular
  expressions cannot recognize.
- Ready-to-copy Codex and Codex Router configuration, including the required
  compression and WebSocket settings.

## How it works

```
Agent --> Cover (redacts secrets) --> real LLM provider
Agent <-- Cover (restores secrets) <-- real LLM provider
```

Cover is a transparent reverse proxy: it forwards whatever method, path,
query string, and headers your agent sends, but rewrites the JSON request
body before it leaves your machine, and rewrites the response body before it
reaches your agent.

1. The request body is parsed (if JSON) and every string value is scanned
   against a set of regex detectors (AWS/GCP/GitHub/GitLab/Slack/Stripe/
   OpenAI/Anthropic keys, private key blocks, JWTs, generic
   `key=value`/`key: value` secret assignments, emails, SSNs, credit
   card numbers, phone numbers, and IBANs — see
   `internal/redact/detectors/regex.go`), plus an optional local LLM pass
   for free-form sensitive content (see below).
2. Each rule chooses `pseudonymize`, `placeholder`, `mask`, `redact`, `block`,
   or `allow`. Reversible replacements are recorded in a bounded, session-local
   in-memory bijection. The same value maps consistently within that session.
3. The redacted body is forwarded to `upstream`.
4. The response (including `text/event-stream` / chunked streaming responses)
   is scanned for reversible fakes and placeholders, which are swapped back for
   their originals before being returned to the agent.

Malformed JSON, detector/generator failures, mapping exhaustion, and blocked
rules are rejected locally. The original request is never used as a fallback.

Redaction mappings live in memory only for the life of the `cover`
process and are never written to disk. Logs record which categories were
redacted and how many, never the values themselves. Request paths, query
strings, and sensitive upstream URL components are also omitted from logs and
status output.

Add your own patterns (e.g. internal project codenames, customer IDs) via
`detectors.regex.custom_patterns` in the config file.

## Install

### One command (recommended)

```sh
curl -fsSL https://raw.githubusercontent.com/DavidCarliez/cover/main/scripts/install.sh | bash
```

For non-interactive installs (CI, scripts), set agents explicitly:

```sh
COVER_AGENTS=claude curl -fsSL https://raw.githubusercontent.com/DavidCarliez/cover/main/scripts/install.sh | bash
```

This will:

1. Clone the repo and build the `cover` binary (requires [Go](https://go.dev/dl/))
2. Install it to `~/.local/bin/cover`
3. Ask which agents you use (OpenAI/Codex, Claude Code, Cursor)
4. Write config, add `BASE_URL` exports to your shell profile, and start the proxy in the background
5. Print a ready summary with the env vars to use

Re-run anytime to reconfigure. From a git checkout you can also run:

```sh
./scripts/install.sh
```

For **Claude Code**, the installer also writes `ANTHROPIC_BASE_URL` to
`~/.claude/settings.json` (the recommended persistent config). Exit any
running `claude` session and start a new one after installing.

### Manual install

Requires Go (see `go.mod` for the version used to build).

```sh
git clone https://github.com/DavidCarliez/cover.git && cd cover
go build -o cover ./cmd/cover
```

This produces a single self-contained `cover` binary with no runtime
dependencies (no cgo, no C toolchain needed). Put it somewhere on your
`PATH`, e.g.:

```sh
sudo mv cover /usr/local/bin/
```

It cross-compiles to any platform/architecture Go supports — e.g. to build
for Linux arm64 from macOS:

```sh
GOOS=linux GOARCH=arm64 go build -o cover-linux-arm64 ./cmd/cover
```

## Quick start

### 1. Configure

```sh
cover init
```

This prompts you for which LLM API to proxy to (OpenAI, Anthropic, or a
custom URL), then writes `~/.config/cover/config.yaml` (see
`configs/config.example.yaml` for the full set of options).

### 2. Start the proxy

```sh
cover start            # foreground
cover start --detach   # background; logs to ~/.local/share/cover/daemon.log
cover restart          # stop (if running) and start in background
cover status
cover doctor           # verify policy, daemon, and Codex routing
cover monitor          # watch safe request metadata; Ctrl-C to stop
cover stop
```

Cover accepts loopback listeners by default. Remote or all-interface listeners
are rejected unless you explicitly set `network.allow_remote: true`; if you do,
protect the listener separately with firewall rules and authentication. Memory
use is bounded with configurable request, response, and SSE-event limits:

```yaml
network:
  allow_remote: false
limits:
  request_bytes: 16777216
  response_bytes: 33554432
  sse_event_bytes: 4194304
```

Oversized requests are rejected locally with HTTP 413. Oversized buffered
responses return HTTP 502, while a stream is terminated if its total response
or individual SSE event exceeds the configured cap.

### 3. Sanity check (optional)

```sh
cover test
```

Runs a built-in sample payload containing fake secrets through the redactor
(no network calls) and prints what gets redacted and restored.

### Diagnose and monitor

```sh
cover doctor
cover doctor --json
```

`cover doctor` validates the configuration, loopback policy, memory limits,
private HMAC key, redaction/restoration round trip, upstream-loop protection,
daemon, local fail-closed behavior, audit-log permissions, API-base environment
variables, and the selected user-level Codex provider. It also verifies that
Codex request compression is disabled so Cover can inspect the body. The live
probe is deliberately malformed and rejected locally; Doctor does not contact
the configured upstream or spend model tokens.

The Codex checks follow the official
[Codex configuration reference](https://developers.openai.com/codex/config-reference/):
provider routing belongs in the user-level `~/.codex/config.toml`, using
`model_provider` and the matching `model_providers.<id>.base_url`.

```sh
cover monitor                         # recent events, then follow
cover monitor --follow=false -n 50   # print the last 50 and exit
cover monitor --json                  # newline-delimited JSON
```

Monitor shows only allowlisted metadata: time, HTTP status, transformation
count, bytes sent upstream, bytes returned locally, latency, matched categories,
and a generic error label. It reconstructs each event instead of printing raw
log lines, so unknown fields—including any historical path or query fields—are
discarded. Older events created before byte metrics were added display `-` for
those columns.

### Define and test privacy rules

Top-level `rules` are declarative and validated at startup. Each rule selects
data using `pattern`, a `builtin_*` detector, or a list of JSON object `keys`.
Rules also support `category`, `priority`, `action`, `generator`, `enabled`,
`case_sensitive`, and `capture_group`. Key rules apply to the entire string
value and match keys case-insensitively by default. If a regular expression
contains `(?P<value>...)`, only that captured value is transformed. Invalid
selectors, regexes, actions, generators, or capture groups stop startup.

```yaml
rules:
  password_fields:
    keys: [password, passwd, pwd, passphrase, user_password, database_password]
    category: password
    action: pseudonymize
    generator: password
    priority: 220
  internal_ip:
    detector: builtin_ipv4
    action: pseudonymize
    generator: ipv4
  password:
    pattern: '(?i)password\s*[:=]\s*(?P<value>[^\s,;]+)'
    action: pseudonymize
    generator: password
  api_key:
    pattern: '(?i)api[_-]?key\s*[:=]\s*(?P<value>[A-Za-z0-9._-]{16,})'
    action: block
    priority: 100
```

Key-aware rules protect short and ordinary values that cannot safely be
identified by shape alone. For example, `{"password":"admin"}` pseudonymizes
the complete `admin` value while leaving an unrelated `{"username":"admin"}`
unchanged. Key rules currently apply to JSON string values; regex rules remain
the fallback for assignments embedded in prose, logs, commands, and tool
output.

Pseudonyms and placeholder IDs are derived with HMAC-SHA-256 using a local
32-byte key. Cover creates `~/.config/cover/pseudonym.key` with owner-only
permissions on first use. The same key produces stable pseudonyms across
sessions and restarts, while separate Cover installations produce different
values. Never commit or share this key. Back it up securely if pseudonym
continuity matters; deleting it intentionally rotates the pseudonym namespace.
Upgrading from an unkeyed Cover release changes existing pseudonyms once when
this key is first created.

Preview exactly what would be sent upstream without making a network request:

```sh
cover inspect request.json
```

The JSON report contains the transformed request, categories, matched rule
names, actions, warnings, and blocked status. It never prints the reversible
mapping or a separate list of original sensitive values.

For a live sanity check, keep one terminal on the safe metadata-only log:

```sh
tail -f ~/.local/share/cover/redactions.log
```

Then ask Codex to echo a synthetic detector value such as
`contact=alice@example.com`. A successful round trip logs
`transformed=1 categories=email`; the provider receives a replacement while
Codex displays the restored synthetic email. Use `cover inspect` when you
need to view the complete transformed JSON locally without forwarding it.

## Hook it up to your agent

Once the proxy is running on `127.0.0.1:8317` (the default — change via
`listen` in the config), point your agent's API base URL at it instead of
the real provider. Your existing API key env vars (`OPENAI_API_KEY`,
`ANTHROPIC_API_KEY`, etc.) keep working as-is — Cover only rewrites the
request/response *bodies* and passes headers straight through, so
authentication with the real provider is unaffected.

### Claude Code

```sh
export ANTHROPIC_BASE_URL=http://127.0.0.1:8317
```

Run `claude` as normal in the same shell/session. Every request from Claude
Code now flows through Cover before reaching `api.anthropic.com`.

### Codex CLI / other OpenAI-API agents

Current Codex uses the Responses API and enables zstd request compression and
WebSockets by default. Define a user-level provider in `~/.codex/config.toml`
that uses ordinary, uncompressed HTTP through Cover:

```toml
model_provider = "cover"

[model_providers.cover]
name = "Cover"
base_url = "http://127.0.0.1:8317"
wire_api = "responses"
requires_openai_auth = true
supports_websockets = false

[features]
enable_request_compression = false
```

If your existing config already has a `[features]` table, add the compression
key there instead of creating a duplicate table. If the router uses an
environment API key rather than Codex/OpenAI login, use
`env_key = "YOUR_ROUTER_KEY_ENV_NAME"` instead of `requires_openai_auth`.

Keep Cover's `upstream` set to the router's real base URL, including its
`/v1` suffix when present. The Codex-facing `base_url` above should not add
`/v1`; Codex appends the Responses path itself.

For SDKs and other clients that expect an OpenAI `/v1` base URL:

```sh
export OPENAI_BASE_URL=http://127.0.0.1:8317/v1
```

For a Codex Router deployment, copy
[`configs/codex-router.example.yaml`](configs/codex-router.example.yaml) and set
its `upstream` to your router:

```text
Codex / OMP
      |
      v
Cover privacy proxy
      |
      v
Codex Router
      |
      v
OpenAI / Anthropic / Gemini / local models / others
```

The proxy recursively scans generic JSON and does not depend on which provider
the router chooses. Send a stable `X-Cover-Session` header when reversible
mappings must work across turns. A request without it receives an isolated
mapping that is destroyed after its response completes.

### Any agent built on the OpenAI or Anthropic SDKs

Most SDKs accept a `base_url` (or `baseURL`) constructor option as an
alternative to the env vars above, e.g.:

```python
client = OpenAI(base_url="http://127.0.0.1:8317/v1", api_key=os.environ["OPENAI_API_KEY"])
client = anthropic.Anthropic(base_url="http://127.0.0.1:8317", api_key=os.environ["ANTHROPIC_API_KEY"])
```

```ts
const client = new OpenAI({ baseURL: "http://127.0.0.1:8317/v1", apiKey: process.env.OPENAI_API_KEY });
const client = new Anthropic({ baseURL: "http://127.0.0.1:8317", apiKey: process.env.ANTHROPIC_API_KEY });
```

### Anything else (generic HTTP)

If your tool lets you set a custom "API base URL" / "endpoint" setting
(custom integrations, IDE plugins, internal scripts), point it at
`http://127.0.0.1:8317` (or `/v1` if it's an OpenAI-shaped client) — Cover
forwards everything else (path, query string, headers, streaming) unchanged.

To confirm traffic is actually flowing through the proxy, tail the redaction
log while your agent runs:

```sh
tail -f ~/.local/share/cover/redactions.log
```

## Optional: local LLM fallback detector

Regex catches structured secrets (keys, tokens, emails, SSNs, credit
cards, phone numbers, IBANs) but misses free-form sensitive content —
names, internal project codenames, customer IDs, addresses. Cover can
optionally run a small local LLM
(`Qwen2.5-0.5B-Instruct`, ~0.5B params, ~490MB as a Q4 GGUF) as an additional
detection pass over each string field.

This is implemented by spawning [`llama-server`](https://github.com/ggml-org/llama.cpp)
— llama.cpp's prebuilt HTTP server binary — as a local subprocess and talking
to it over `127.0.0.1`. The core `cover` binary itself has no C
dependencies and cross-compiles to any platform Go supports; the LLM fallback
is available wherever ggml-org/llama.cpp publishes a prebuilt CPU binary
(macOS arm64/x64, Linux x64/arm64/s390x, Windows x64/arm64). On any other
platform, or if the binary/model have not been downloaded, leave the fallback
disabled. When it is enabled, failure to start or query it causes startup or
the affected request to fail closed rather than silently weakening the policy.

### Set it up

```sh
cover models pull     # downloads llama-server + the GGUF model (~490MB)
cover models status    # check what's installed and whether enabled
```

`models pull` updates `server_path`/`model_path` in your config and asks
whether to set `detectors.llm_fallback.enabled: true`. Restart Cover
afterwards (`cover restart`).

### What it costs

- ~500MB of disk for the model, plus a few MB for `llama-server`.
- Each request gets one bounded "budget" (`overall_timeout_ms`, default
  4000ms) for all LLM detector calls combined. A timeout or unavailable local
  server rejects that request locally.
- String fields outside `min_text_len`/`max_text_len` (default 8–2000 bytes)
  are skipped entirely.
- Matches are flagged under the `llm_sensitive` category. Every candidate the
  model returns is verified to be a verbatim substring of the original text
  before being redacted, to guard against hallucinated spans.

See `configs/config.example.yaml` for all `llm_fallback` options.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for
development setup, testing, and pull request guidelines.

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

## Security

### Assumptions, exclusions, and limitations

The proxy protects JSON request bodies that pass through it. It intentionally
does not transform structural protocol identifiers: `model`, `role`, `type`,
protocol-context tool/function `name`, `id`, `tool_use_id`, `call_id`, `item_id`,
`stop_reason`, and `stop_sequence`. Changing those fields can break model routing, tool dispatch,
or response correlation. Do not place secrets in them. Text-bearing fields such
as `instructions`, `system`, message content, tool arguments/results, command
output, file content, assistant context, and user metadata are scanned.

Data that can still leave the machine includes:

- sensitive values that no enabled regex or local detector recognizes (false
  negatives), including organization-specific terms without a custom rule;
- values intentionally covered by an `allow` rule, and unprotected structural
  identifiers listed above;
- HTTP headers, URL paths, and query strings, which are transparently forwarded;
- image pixels and other binary media. **Image pixels are not inspected for
  sensitive content.** Set `media.images: block` to reject recognized inline
  images and image URLs; detection of every possible media encoding is not
  guaranteed;
- non-string JSON values and encrypted/encoded text that does not match a rule;
- compressed request bodies. They fail closed; for Codex, set
  `features.enable_request_compression = false` as shown above;
- data sent directly to a provider because a client was not actually configured
  to use this proxy.

Mappings stay in memory, are separated by the configured session header, expire
after the configured TTL, and have hard session/entry limits. Only the random
HMAC derivation key is persisted; it cannot restore values by itself. Default
logs contain status, transformed count, byte counts, latency, matched
categories, and generic errors only—not paths, queries, request bodies, tool
arguments, mapping contents, original values, or restored response bodies.
There is no unsafe raw-debug logging mode by default.

Use TLS or a trusted local transport if the proxy and router are on different
hosts. Authentication headers pass through unchanged and remain visible to the
upstream router/provider.

If you discover a security vulnerability, please follow our
[security policy](SECURITY.md) and report it privately — do not open a public
issue.

## License

Cover is licensed under the [Apache License 2.0](LICENSE).
