import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

const execFileAsync = promisify(execFile);
const PROVIDER_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const STATUS_KEY = "cover";

export function configDirectory(env = process.env) {
  const base = env.XDG_CONFIG_HOME || join(env.HOME || homedir(), ".config");
  return join(base, "cover");
}

export function statePath(env = process.env) {
  return env.COVER_HARNESS_STATE || join(configDirectory(env), "harness.json");
}

export function defaultRoutePath(provider) {
  return provider === "openai" || provider.startsWith("openai-") ? "/v1" : "";
}

export function parseProviderSpec(input) {
  const routes = {};
  for (const raw of String(input || "").split(",")) {
    const token = raw.trim();
    if (!token) continue;
    const equals = token.indexOf("=");
    const provider = (equals === -1 ? token : token.slice(0, equals)).trim().toLowerCase();
    if (!PROVIDER_RE.test(provider)) throw new Error(`invalid provider name: ${provider || "<empty>"}`);
    let path = equals === -1 ? defaultRoutePath(provider) : token.slice(equals + 1).trim();
    if (path === "/") path = "";
    if (path && (!path.startsWith("/") || path.includes("?") || path.includes("#") || path.includes(".."))) {
      throw new Error(`invalid proxy path for ${provider}: ${path}`);
    }
    routes[provider] = path.replace(/\/$/, "");
  }
  return routes;
}

export function inferRoutes(upstream) {
  let host;
  try {
    host = new URL(upstream).hostname.toLowerCase();
  } catch {
    return {};
  }
  if (host === "api.openai.com") return { openai: "/v1" };
  if (host === "api.anthropic.com") return { anthropic: "" };
  if (host === "api.deepseek.com") return { deepseek: "" };
  if (host === "openrouter.ai") return { openrouter: "" };
  return {};
}

export function readState(path, env = process.env) {
  let stored = {};
  try {
    stored = JSON.parse(readFileSync(path, "utf8"));
  } catch {}

  let routes = {};
  if (stored.routes && typeof stored.routes === "object" && !Array.isArray(stored.routes)) {
    routes = parseProviderSpec(Object.entries(stored.routes).map(([key, value]) => `${key}=${value || "/"}`).join(","));
  } else if (Array.isArray(stored.providers)) {
    routes = parseProviderSpec(stored.providers.join(","));
  }
  if (env.COVER_PROVIDERS) routes = parseProviderSpec(env.COVER_PROVIDERS);

  return {
    enabled: env.COVER_HARNESS_DISABLED ? false : stored.enabled !== false,
    autoFallback: stored.autoFallback === true,
    routes,
  };
}

export function writeState(path, state) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  renameSync(temporary, path);
}

export function proxyEndpoint(baseURL, path) {
  return `${String(baseURL).replace(/\/$/, "")}${path || ""}`;
}

function binaryName(env) {
  return env.COVER_BIN || "cover";
}

export function readCoverStatusSync(env = process.env) {
  const binary = binaryName(env);
  try {
    const output = execFileSync(binary, ["status", "--json"], {
      encoding: "utf8",
      env,
      timeout: 5000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { installed: true, ...JSON.parse(output) };
  } catch (error) {
    return {
      installed: error?.code !== "ENOENT",
      running: false,
      base_url: env.COVER_BASE_URL || "http://127.0.0.1:8317",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

async function runCover(args, env = process.env, timeout = 15000) {
  const { stdout, stderr } = await execFileAsync(binaryName(env), args, {
    encoding: "utf8",
    env,
    timeout,
    maxBuffer: 1024 * 1024,
  });
  return `${stdout}${stderr}`.trim();
}

function shortMessage(value, limit = 3500) {
  const text = String(value || "").trim();
  return text.length > limit ? `${text.slice(0, limit)}\n…` : text;
}

function notify(ctx, message, level = "info") {
  if (ctx?.ui?.notify) ctx.ui.notify(shortMessage(message), level);
}

function indicatorIcon(state) {
  // The state describes only the active model's provider route.
  // A registered fail-closed route stays locked even while Cover is unavailable.
  return state === "protected" || state === "blocked" ? "\u{1F512}" : "\u{1F513}";
}

export function createCoverExtension(pi, options = {}) {
  const env = options.env || process.env;
  const savedStatePath = options.statePath || statePath(env);
  let state = readState(savedStatePath, env);
  const readStatus = options.readStatus || (() => readCoverStatusSync(env));
  let status = readStatus();
  let bypassed = state.enabled && state.autoFallback && !status.running;
  const explicitBaseURL = env.COVER_BASE_URL;
  let baseURL = explicitBaseURL || status.base_url || "http://127.0.0.1:8317";
  const registered = new Set();

  if (Object.keys(state.routes).length === 0) {
    state.routes = inferRoutes(status.upstream);
  }

  const applyRoutes = () => {
    for (const provider of [...registered]) {
      if (!state.enabled || bypassed || !(provider in state.routes)) {
        pi.unregisterProvider(provider);
        registered.delete(provider);
      }
    }
    if (!state.enabled || bypassed) return;
    for (const [provider, path] of Object.entries(state.routes)) {
      pi.registerProvider(provider, { baseUrl: proxyEndpoint(baseURL, path) });
      registered.add(provider);
    }
  };

  const save = () => writeState(savedStatePath, state);
  const currentModel = (ctx) => typeof ctx?.models?.current === "function" ? ctx.models.current() : ctx?.model;
  const coverage = (ctx, model = currentModel(ctx)) => {
    if (!state.enabled) return "off";
    if (bypassed) return "direct";
    if (Object.keys(state.routes).length === 0) return "setup";
    if (!model) return "unknown";
    if (!registered.has(model.provider)) return "unconfigured";
    return status.running ? "protected" : "blocked";
  };
  const updateIndicator = (ctx, model) => {
    if (ctx?.mode === "tui" && typeof ctx?.models?.current === "function" && typeof ctx?.ui?.setWidget === "function") {
      // OMP redraws on role/model changes but does not emit Pi's model_select.
      // Read its live model during rendering instead of caching a stale icon.
      ctx.ui.setStatus?.(STATUS_KEY, undefined);
      ctx.ui.setWidget(STATUS_KEY, () => ({
        render: () => [indicatorIcon(coverage(ctx))],
        invalidate() {},
      }), { placement: "belowEditor" });
      return;
    }
    ctx?.ui?.setStatus?.(STATUS_KEY, indicatorIcon(coverage(ctx, model)));
  };
  const describeCoverage = (ctx) => {
    const provider = currentModel(ctx)?.provider || "none";
    switch (coverage(ctx)) {
      case "off": return `Active provider: ${provider} — Cover is off; not protected by this plugin.`;
      case "direct": return `Active provider: ${provider} — direct fallback is active; not protected by this plugin.`;
      case "setup": return `Active provider: ${provider} — setup needed; no Cover providers are configured.`;
      case "unknown": return "Active provider: none — coverage cannot be determined until a model is selected.";
      case "unconfigured": return `Active provider: ${provider} — not configured for Cover; not protected by this plugin.`;
      case "blocked": return `Active provider: ${provider} — routed through Cover, fail-closed while Cover is unavailable.`;
      default: return `Active provider: ${provider} — routed through Cover.`;
    }
  };
  const refreshActiveModel = async (ctx) => {
    const current = ctx?.model || ctx?.models?.current?.();
    if (!current || typeof pi.setModel !== "function") return;
    const refreshed = ctx?.modelRegistry?.find?.(current.provider, current.id)
      || ctx?.models?.resolve?.(`${current.provider}/${current.id}`);
    if (refreshed) await pi.setModel(refreshed);
  };
  applyRoutes();

  const reconcile = async (ctx) => {
    status = readStatus();
    if (!explicitBaseURL && !status.error && status.base_url) baseURL = status.base_url;
    let available = status.running;
    if (state.enabled && state.autoFallback && available) {
      try {
        // Local-only malformed input checks the proxy without forwarding data.
        available = options.probe ? await options.probe() : (await fetch(`${baseURL.replace(/\/$/, "")}/__cover_doctor__`, {
          method: "POST", body: '{"input":', signal: AbortSignal.timeout(1500), redirect: "error",
        })).status === 422;
      } catch { available = false; }
    }
    const next = state.enabled && state.autoFallback && !available;
    const changed = next !== bypassed;
    bypassed = next;
    applyRoutes();
    await refreshActiveModel(ctx);
    updateIndicator(ctx);
    if (changed && bypassed) notify(ctx, `Cover is unavailable. Automatic fallback restored direct routes for configured providers.\n${describeCoverage(ctx)}`, "warning");
    if (changed && !bypassed && state.enabled) notify(ctx, `Cover routes restored for configured providers.\n${describeCoverage(ctx)}`);
  };

  // Reconcile before a new user turn, never retry a failed request directly.
  pi.on("before_agent_start", async (_event, ctx) => { await reconcile(ctx); });
  pi.on("model_select", (event, ctx) => { updateIndicator(ctx, event.model); });
  pi.on("session_shutdown", (_event, ctx) => {
    ctx?.ui?.setWidget?.(STATUS_KEY, undefined);
    ctx?.ui?.setStatus?.(STATUS_KEY, undefined);
  });

  pi.on("session_start", async (_event, ctx) => {
    // OMP resolves the initial model before it drains queued extension provider
    // overrides. Reapply and reselect here so the first request uses Cover too.
    await reconcile(ctx);
    if (bypassed) {
      notify(ctx, `Cover is unavailable. Automatic fallback is enabled.\n${describeCoverage(ctx)}`, "warning");
      return;
    }
    if (!state.enabled) return;
    if (Object.keys(state.routes).length === 0) {
      notify(ctx, `No Cover providers are configured. Run /cover providers <provider> and then /cover on.\n${describeCoverage(ctx)}`, "warning");
      return;
    }
    if (!status.installed) {
      notify(ctx, `The cover binary was not found. Install it from https://github.com/DavidCarliez/cover. Configured provider routes remain pointed at Cover.\n${describeCoverage(ctx)}`, "error");
      return;
    }
    if (!status.running) {
      notify(ctx, `The Cover daemon is stopped. Run /cover start. Configured provider routes remain pointed at Cover.\n${describeCoverage(ctx)}`, "error");
      return;
    }
    if (coverage(ctx) !== "protected") notify(ctx, describeCoverage(ctx), "warning");
  });

  pi.registerCommand("cover", {
    description: "Control and inspect the Cover privacy proxy",
    handler: async (args, ctx) => {
      const [action = "status", ...rest] = String(args || "").trim().split(/\s+/).filter(Boolean);
      try {
        switch (action.toLowerCase()) {
          case "status": {
            await reconcile(ctx);
            const providers = Object.keys(state.routes).join(", ") || "none";
            notify(ctx, `${describeCoverage(ctx)}\nAutomatic fallback: ${state.autoFallback ? "on" : "off"}\nConfigured providers: ${providers}\nProxy: ${baseURL}\nDaemon: ${status.running ? "running" : "stopped"}`,
              coverage(ctx) === "protected" ? "info" : "warning");
            break;
          }
          case "on":
            if (Object.keys(state.routes).length === 0) throw new Error("configure providers first: /cover providers <provider>");
            state.enabled = true;
            save();
            await reconcile(ctx);
            notify(ctx, `Cover enabled for configured providers.\n${describeCoverage(ctx)}`, coverage(ctx) === "protected" ? "info" : "warning");
            break;
          case "off":
            state.enabled = false;
            bypassed = false;
            save();
            applyRoutes();
            await refreshActiveModel(ctx);
            updateIndicator(ctx);
            notify(ctx, "Cover protection disabled. Configured providers now connect directly.", "warning");
            break;
          case "fallback": {
            if (!["on", "off"].includes(rest[0]) || rest.length !== 1) throw new Error("Usage: /cover fallback on|off");
            state.autoFallback = rest[0] === "on";
            save();
            await reconcile(ctx);
            notify(ctx, state.autoFallback ? "Automatic fallback enabled. If Cover is unavailable, configured providers connect directly on new turns without Cover protection." : "Automatic fallback disabled. When Cover is enabled, configured provider routes remain pointed at Cover if it stops. Unconfigured providers are not covered.", state.autoFallback ? "warning" : "info");
            break;
          }
          case "providers": {
            const spec = rest.join(" ");
            if (!spec) {
              notify(ctx, `Configured providers: ${Object.entries(state.routes).map(([provider, path]) => `${provider}=${path || "/"}`).join(", ") || "none"}`);
              break;
            }
            state.routes = parseProviderSpec(spec);
            save();
            applyRoutes();
            await refreshActiveModel(ctx);
            updateIndicator(ctx);
            notify(ctx, `Cover providers updated: ${Object.keys(state.routes).join(", ") || "none"}.\n${describeCoverage(ctx)}`);
            break;
          }
          case "start":
            await runCover(["start", "--detach"], env, 30000);
            await reconcile(ctx);
            notify(ctx, status.running ? "Cover daemon started." : "Cover did not report a running daemon.", status.running ? "info" : "error");
            break;
          case "stop":
            await runCover(["stop"], env, 120000);
            await reconcile(ctx);
            notify(ctx, bypassed ? "Cover daemon stopped; new turns connect directly without protection." : state.enabled ? "Cover daemon stopped; configured providers remain fail-closed." : "Cover daemon stopped.", "warning");
            break;
          case "doctor":
            notify(ctx, (await runCover(["doctor"], env, 30000)) || "Cover doctor completed.");
            break;
          case "monitor":
            notify(ctx, (await runCover(["monitor", "--follow=false", "-n", "10"], env)) || "No recent Cover activity.");
            break;
          case "help":
            notify(ctx, "Usage: /cover [status|on|off|fallback on|fallback off|providers <id[=/path],…>|start|stop|doctor|monitor]");
            break;
          default:
            throw new Error(`unknown Cover action: ${action}. Run /cover help.`);
        }
      } catch (error) {
        notify(ctx, error instanceof Error ? error.message : String(error), "error");
      }
    },
  });

  return { getState: () => structuredClone(state), getStatus: () => structuredClone(status), applyRoutes };
}
