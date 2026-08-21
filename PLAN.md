# Privacy hardening plan

## Current architecture

`llmguard` is a transparent Go HTTP reverse proxy. `internal/proxy` reads a
request body, delegates recursive JSON string rewriting to `internal/redact`,
forwards the rewritten bytes, and restores mapped values in ordinary or SSE
responses. `internal/redact/detectors` supplies built-in and custom regular
expressions. A process-wide in-memory store maps short placeholder hashes back
to originals. `internal/config` loads YAML and `cmd/llmguard` assembles the
components and exposes lifecycle commands.

## Security-sensitive paths

- Configuration loading and detector compilation determine the active policy.
- Request parsing and recursive traversal decide which bytes may leave the host.
- Match overlap resolution, action selection, generation, and mapping determine
  whether sensitive values are transformed reversibly.
- Protocol-field exclusions decide which JSON strings are intentionally trusted.
- Proxy error paths determine whether malformed or uninspectable data is ever
  forwarded.
- Normal, chunked, and SSE restoration must handle replacements split across
  transport chunks without exposing mapping contents.
- Mapping ownership and cleanup determine whether concurrent conversations leak
  values across sessions or grow memory without a bound.
- Logging and inspection output must report useful metadata without raw secrets.

## Proposed changes

1. Replace infallible body rewriting with a result/error API. Require valid JSON
   for protected non-empty request bodies and reject detector, generator,
   mapping, or marshal failures locally.
2. Introduce validated declarative rules with action, generator, priority,
   category, enabled state, case sensitivity, and named `value` capture support.
3. Add reversible format-preserving generators for IP addresses, hosts/domains,
   email, username, password, UUID, URL, and deterministic aliases, while
   retaining opaque placeholders and adding allow/mask/redact/block actions.
4. Narrow the protocol exclusion list to identifiers whose mutation would break
   routing. Continue scanning instructions, system text, tool arguments/results,
   command output, file contents, and user metadata.
5. Scope bounded bijective mappings by a configurable session header, with a
   safe default isolated session and TTL/entry cleanup. Avoid collisions with
   originals observed in the request.
6. Restore every reversible fake as well as placeholders in JSON, raw chunked,
   and SSE responses, including tokens split across writes.
7. Add allow/block/warn media policy for inline image data and image URLs. Image
   pixels remain uninspected.
8. Add `llmguard inspect request.json`, safe structured logging, a Codex Router
   example, and explicit limitations.
9. Add protocol-shaped, concurrency, collision, cleanup, streaming, media, and
   fail-closed tests, then run the complete test and vet suites.

## Compatibility risks

- Strict JSON enforcement can reject previously forwarded opaque request bodies;
  this is intentional fail-closed behavior for protected LLM API traffic.
- Existing `detectors.regex.custom_patterns` remains readable, but new `rules`
  is the preferred policy format. Existing built-ins default to placeholder
  action unless explicitly overridden.
- Session isolation means a client that needs restoration across turns must send
  a stable configured session header; the default session remains compatible
  with single-agent deployments but has bounded lifetime.
- Format-preserving fakes can have different byte lengths. Content-Length is
  recalculated, and streaming writers retain enough data to recognize mapped
  values across chunks.
- Narrower protocol exclusions can transform sensitive-looking text in fields
  that were previously skipped. Only structural identifiers remain excluded.
