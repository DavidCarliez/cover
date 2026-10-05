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
State is stored in `~/.config/cover/harness.json` with private permissions.

For automatic direct routing when Cover is unavailable, opt in with
`/cover fallback on`. Before each new user turn, the plugin checks Cover. It
restores the provider's original connection settings if Cover is unavailable,
and shows **DIRECT — unprotected**. When Cover returns, protection resumes on
the next user turn. `/cover fallback off` restores the default fail-closed mode.
Existing requests and tool continuations are not replayed directly on failure.
The provider's original connection settings must work independently of Cover.

On each successful status check, the plugin adopts the proxy URL advertised by
the daemon, so listener changes take effect on the next turn. If status cannot
be read, it retains the last-known URL. `COVER_BASE_URL` always takes priority.

OMP's plugin enable/disable controls manage plugin loading. They are separate
from starting/stopping the Cover daemon or its automatic fallback policy.

Environment overrides:

- `COVER_BIN`: path to the Cover executable.
- `COVER_BASE_URL`: local proxy URL.
- `COVER_PROVIDERS`: comma-separated provider routes.
- `COVER_HARNESS_DISABLED`: start with integration disabled.
- `COVER_HARNESS_STATE`: alternate state file.
