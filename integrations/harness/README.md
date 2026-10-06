# Cover Plugin for Pi and Oh My Pi

`cover-plugin` connects [Cover](https://github.com/DavidCarliez/cover) to the Pi
and Oh My Pi model-provider systems. Cover remains the local privacy boundary;
the plugin only manages provider routing, health, and commands.

Install Cover first, then install the extension:

```sh
pi install npm:cover-plugin

# Oh My Pi: install directly from npm
omp plugin install cover-plugin

# Or use the Cover marketplace
omp plugin marketplace add DavidCarliez/cover
omp plugin install cover-plugin@cover
```

Inside Pi or Oh My Pi, choose exactly which providers must use Cover:

```text
/cover providers openai-codex,deepseek=/
/cover on
/cover doctor
```

OpenAI-family providers default to the `/v1` proxy path. Use `=/` for providers
whose transport supplies its own API path. Custom paths are also supported, for
example `router=/api/v1`.

Commands: `/cover status`, `/cover on`, `/cover off`, `/cover fallback on|off`, `/cover providers`,
`/cover start`, `/cover stop`, `/cover doctor`, and `/cover monitor`.

When protection is enabled, configured providers remain pointed at the local
proxy if Cover stops. Their requests fail locally instead of bypassing Cover.
Providers not in `/cover providers` keep their own routes: enabling Cover does
not protect them or make them fail-closed. `/cover status` reports the active
model's provider coverage separately from the configured provider list.
State is stored in `~/.config/cover/harness.json` with private permissions.

For automatic direct routing when Cover is unavailable, opt in with
`/cover fallback on`. Before each new user turn, the plugin checks Cover. It
restores the provider's original connection settings if Cover is unavailable,
and shows **&#x1F513;**. The compact status indicator describes the **active
model's provider**, not the whole session: **&#x1F512;** means that provider has
a registered Cover route, including a fail-closed route while Cover is stopped
or its binary is unavailable. **&#x1F513;** means Cover is off, direct fallback
is active, the active provider is unconfigured, or provider/model setup is
missing. A running daemon alone does not make an unconfigured provider covered.
The indicator refreshes at session start, before turns, after routing commands,
and when the active model changes. Pi uses its model-selection event; OMP's
below-editor widget reads the live model whenever the TUI redraws, including
role switches. No polling or provider-route changes are needed to refresh it.
Notifications and `/cover status` retain coverage and daemon details.
When Cover returns, protection resumes on the next user turn. `/cover fallback
off` restores the default fail-closed mode. Existing requests and tool
continuations are not replayed directly on failure. The provider's original
connection settings must work independently of Cover.

On each successful status check, the plugin adopts the proxy URL advertised by
the daemon, so listener changes take effect on the next turn. If status cannot
be read, it retains the last-known URL. `COVER_BASE_URL` always takes priority.

OMP's plugin enable/disable controls manage plugin loading. They are separate
from starting/stopping the Cover daemon or its automatic fallback policy.

After updating the installed plugin, restart Pi or OMP so the session loads the
new code and event handlers. Routing commands take effect in the current
session; restarting the Cover daemon alone does not reload the plugin.

Environment overrides:

- `COVER_BIN`: path to the Cover executable.
- `COVER_BASE_URL`: local proxy URL.
- `COVER_PROVIDERS`: comma-separated provider routes.
- `COVER_HARNESS_DISABLED`: start with integration disabled.
- `COVER_HARNESS_STATE`: alternate state file.

## Structured tool-result policies

Cover inspects nested JSON, recognized HTTP/curl text, and supported HTML in tool
results. Configure `keys`, `headers`, `cookies`, `query_params`, or `form_fields`
rules in Cover's YAML configuration; no plugin-specific policy is needed.
HTML form identities reuse `keys`/`form_fields`, while entity-decoded attributes
and text joined across inline markup use the existing detectors. Typed JSON
scripts retain structured field policies. This inspection requires no local LLM.
Streamed tool arguments are restored only after their JSON is complete.
Malformed protected content is rejected locally, including when automatic
fallback is enabled: fallback does not retry policy errors directly.

## End-to-end verification

From the repository root:

```sh
go build -o /tmp/cover-test ./cmd/cover
COVER_HARNESS_E2E=1 COVER_TEST_BINARY=/tmp/cover-test \
  node --test integrations/harness/test/e2e.test.js \
  integrations/harness/test/tool-results.e2e.test.js
```

The suite launches installed Pi/OMP clients with isolated configuration and
loopback model/HTTP fixtures. JSON and HTML cases run through curl and real MCP
tool calls. It checks what the model receives and what a subsequent real tool
invocation sends after restoration, including the next conversation turn.
HTML fixtures include entity-escaped credentials, password controls with
different names, numeric JSON-script values and text split across inline tags.
Install `pi`, `omp`, and `curl` before running the suite.

To include an already-running HTTP-capable MCP server:

```sh
COVER_HARNESS_E2E=1 COVER_TEST_BINARY=/tmp/cover-test \
  COVER_HTTP_MCP_URL=http://127.0.0.1:9000/ \
  node --test --test-name-pattern='protects http-mcp' \
  integrations/harness/test/tool-results.e2e.test.js
```

This optional adapter expects an SSE MCP endpoint with a `send_http1_request`
tool that accepts `content`, `targetHostname`, `targetPort`, and `usesHttps`.
Use the address of your local server. Approve its loopback fixture request if
prompted; the test does not disable server approval or contact an assessment
target.
