# Cover for Pi and Oh My Pi

This package connects [Cover](https://github.com/DavidCarliez/cover) to the Pi
and Oh My Pi model-provider systems. Cover remains the local privacy boundary;
the extension only manages provider routing, health, and commands.

Install Cover first, then install the extension:

```sh
pi install npm:cover-harness
# or
omp plugin install cover-harness
```

Inside the harness, choose exactly which providers must use Cover:

```text
/cover providers openai-codex,deepseek=/
/cover on
/cover doctor
```

OpenAI-family providers default to the `/v1` proxy path. Use `=/` for providers
whose transport supplies its own API path. Custom paths are also supported, for
example `router=/api/v1`.

Commands: `/cover status`, `/cover on`, `/cover off`, `/cover providers`,
`/cover start`, `/cover stop`, `/cover doctor`, and `/cover monitor`.

When protection is enabled, configured providers remain pointed at the local
proxy if Cover stops. Their requests fail locally instead of bypassing Cover.
State is stored in `~/.config/cover/harness.json` with private permissions.

Environment overrides:

- `COVER_BIN`: path to the Cover executable.
- `COVER_BASE_URL`: local proxy URL.
- `COVER_PROVIDERS`: comma-separated provider routes.
- `COVER_HARNESS_DISABLED`: start with integration disabled.
- `COVER_HARNESS_STATE`: alternate state file.
