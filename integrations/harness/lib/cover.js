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

function setIndicator(ctx, state, detail = "") {
  if (!ctx?.ui?.setStatus) return;
  const label = state === "protected" ? "cover: protected" : state === "off" ? "cover: off" : "cover: blocked";
  ctx.ui.setStatus(STATUS_KEY, detail ? `${label} (${detail})` : label);
}

export function createCoverExtension(pi, options = {}) {
  const env = options.env || process.env;
  const savedStatePath = options.statePath || statePath(env);
  let state = readState(savedStatePath, env);
  let status = readCoverStatusSync(env);
  const explicitBaseURL = env.COVER_BASE_URL;
  const baseURL = explicitBaseURL || status.base_url || "http://127.0.0.1:8317";
  const registered = new Set();

  if (Object.keys(state.routes).length === 0) {
    state.routes = inferRoutes(status.upstream);
  }

  const applyRoutes = () => {
    for (const provider of [...registered]) {
      if (!state.enabled || !(provider in state.routes)) {
        pi.unregisterProvider(provider);
        registered.delete(provider);
      }
    }
    if (!state.enabled) return;
    for (const [provider, path] of Object.entries(state.routes)) {
      pi.registerProvider(provider, { baseUrl: proxyEndpoint(baseURL, path) });
      registered.add(provider);
    }
  };

  const save = () => writeState(savedStatePath, state);
  const refreshActiveModel = async (ctx) => {
    const current = ctx?.model || ctx?.models?.current?.();
    if (!current || typeof pi.setModel !== "function") return;
    const refreshed = ctx?.modelRegistry?.find?.(current.provider, current.id)
      || ctx?.models?.resolve?.(`${current.provider}/${current.id}`);
    if (refreshed) await pi.setModel(refreshed);
  };
  applyRoutes();

  pi.on("session_start", async (_event, ctx) => {
    // OMP resolves the initial model before it drains queued extension provider
    // overrides. Reapply and reselect here so the first request uses Cover too.
    applyRoutes();
    await refreshActiveModel(ctx);
    status = readCoverStatusSync(env);
    if (!state.enabled) {
      setIndicator(ctx, "off");
      return;
    }
    if (Object.keys(state.routes).length === 0) {
      setIndicator(ctx, "blocked", "setup needed");
      notify(ctx, "Cover loaded, but no providers are configured. Run /cover providers <provider> and then /cover on.", "warning");
      return;
    }
    if (!status.installed) {
      setIndicator(ctx, "blocked", "binary missing");
      notify(ctx, "Cover is enabled and remains fail-closed, but the cover binary was not found. Install it from https://github.com/DavidCarliez/cover.", "error");
      return;
    }
    if (!status.running) {
      setIndicator(ctx, "blocked", "daemon stopped");
      notify(ctx, "Cover is enabled and remains fail-closed, but the daemon is stopped. Run /cover start.", "error");
      return;
    }
    setIndicator(ctx, "protected", Object.keys(state.routes).join(","));
  });

  pi.registerCommand("cover", {
    description: "Control and inspect the Cover privacy proxy",
    handler: async (args, ctx) => {
      const [action = "status", ...rest] = String(args || "").trim().split(/\s+/).filter(Boolean);
      try {
        switch (action.toLowerCase()) {
          case "status": {
            status = readCoverStatusSync(env);
            const providers = Object.keys(state.routes).join(", ") || "none";
            const mode = state.enabled ? (status.running ? "protected" : "fail-closed") : "off";
            setIndicator(ctx, state.enabled && status.running ? "protected" : state.enabled ? "blocked" : "off");
            notify(ctx, `Cover: ${mode}\nProviders: ${providers}\nProxy: ${baseURL}\nDaemon: ${status.running ? "running" : "stopped"}`,
              state.enabled && !status.running ? "warning" : "info");
            break;
          }
          case "on":
            if (Object.keys(state.routes).length === 0) throw new Error("configure providers first: /cover providers <provider>");
            state.enabled = true;
            save();
            applyRoutes();
            await refreshActiveModel(ctx);
            status = readCoverStatusSync(env);
            setIndicator(ctx, status.running ? "protected" : "blocked");
            notify(ctx, status.running ? "Cover protection enabled." : "Cover protection enabled fail-closed; start the daemon with /cover start.", status.running ? "info" : "warning");
            break;
          case "off":
            state.enabled = false;
            save();
            applyRoutes();
            await refreshActiveModel(ctx);
            setIndicator(ctx, "off");
            notify(ctx, "Cover protection disabled. Configured providers now connect directly.", "warning");
            break;
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
            notify(ctx, `Cover providers updated: ${Object.keys(state.routes).join(", ") || "none"}.`);
            break;
          }
          case "start":
            await runCover(["start", "--detach"], env, 30000);
            status = readCoverStatusSync(env);
            setIndicator(ctx, state.enabled && status.running ? "protected" : state.enabled ? "blocked" : "off");
            notify(ctx, status.running ? "Cover daemon started." : "Cover did not report a running daemon.", status.running ? "info" : "error");
            break;
          case "stop":
            await runCover(["stop"], env);
            status = readCoverStatusSync(env);
            setIndicator(ctx, state.enabled ? "blocked" : "off", state.enabled ? "daemon stopped" : "");
            notify(ctx, state.enabled ? "Cover daemon stopped; configured providers remain fail-closed." : "Cover daemon stopped.", "warning");
            break;
          case "doctor":
            notify(ctx, (await runCover(["doctor"], env, 30000)) || "Cover doctor completed.");
            break;
          case "monitor":
            notify(ctx, (await runCover(["monitor", "--follow=false", "-n", "10"], env)) || "No recent Cover activity.");
            break;
          case "help":
            notify(ctx, "Usage: /cover [status|on|off|providers <id[=/path],…>|start|stop|doctor|monitor]");
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
