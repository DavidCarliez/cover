import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  createCoverExtension,
  defaultRoutePath,
  inferRoutes,
  parseProviderSpec,
  proxyEndpoint,
  readState,
} from "../lib/cover.js";

async function startLocalEndpoint(t) {
  let healthy = true;
  let doctorRequests = 0;
  let providerRequests = 0;
  const server = createServer((request, response) => {
    if (request.url === "/__cover_doctor__") {
      doctorRequests += 1;
      response.writeHead(healthy ? 422 : 503);
    } else {
      providerRequests += 1;
      response.writeHead(204);
    }
    response.end();
  });
  await new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(0, "127.0.0.1");
  });
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  }));
  const { port } = server.address();
  return {
    baseURL: `http://127.0.0.1:${port}`,
    doctorRequests: () => doctorRequests,
    providerRequests: () => providerRequests,
    setHealthy(value) { healthy = value; },
  };
}

test("provider specifications are normalized and validated", () => {
  assert.deepEqual(parseProviderSpec("openai, anthropic=/, deepseek=/api"), {
    openai: "/v1",
    anthropic: "",
    deepseek: "/api",
  });
  assert.equal(defaultRoutePath("openai-codex"), "/v1");
  assert.equal(proxyEndpoint("http://127.0.0.1:8317/", "/v1"), "http://127.0.0.1:8317/v1");
  assert.throws(() => parseProviderSpec("bad provider"), /invalid provider/);
  assert.throws(() => parseProviderSpec("openai=../direct"), /invalid proxy path/);
});

test("known direct upstreams infer conservative provider routes", () => {
  assert.deepEqual(inferRoutes("https://api.openai.com"), { openai: "/v1" });
  assert.deepEqual(inferRoutes("https://api.anthropic.com"), { anthropic: "" });
  assert.deepEqual(inferRoutes("http://127.0.0.1:4102/private"), {});
});

test("environment routes override persisted routes", () => {
  const dir = mkdtempSync(join(tmpdir(), "cover-state-"));
  const path = join(dir, "harness.json");
  const state = readState(path, { HOME: dir, COVER_PROVIDERS: "openai-codex,deepseek=/" });
  assert.deepEqual(state.routes, { "openai-codex": "/v1", deepseek: "" });
  assert.equal(state.autoFallback, false);
});

test("opt-in fallback switches new turns directly and restores protection on recovery", async () => {
  const dir = mkdtempSync(join(tmpdir(), "cover-fallback-"));
  const path = join(dir, "harness.json");
  const registered = new Map(), commands = new Map(), events = new Map();
  let running = true, reachable = true, activeURL;
  const indicators = [];
  const pi = {
    registerProvider(name, config) { registered.set(name, config); },
    unregisterProvider(name) { registered.delete(name); },
    registerCommand(name, command) { commands.set(name, command); },
    on(name, handler) { events.set(name, handler); },
    async setModel(model) { activeURL = model.baseUrl; return true; },
  };
  const ctx = {
    model: { provider: "example", id: "test" },
    modelRegistry: { find() { return { provider: "example", id: "test", baseUrl: registered.get("example")?.baseUrl || "https://direct.example" }; } },
    ui: { notify() {}, setStatus(_name, value) { indicators.push(value); } },
  };
  createCoverExtension(pi, { env: { HOME: dir, COVER_PROVIDERS: "example=/", COVER_BASE_URL: "http://127.0.0.1:9999" }, statePath: path,
    readStatus: () => ({ running, installed: true }), probe: async () => reachable });
  running = false;
  await events.get("before_agent_start")({}, ctx);
  assert.equal(activeURL, "http://127.0.0.1:9999", "default must remain fail-closed");
  await commands.get("cover").handler("fallback on", ctx);
  assert.equal(activeURL, "https://direct.example");
  assert.match(indicators.at(-1), /DIRECT/);
  assert.equal(JSON.parse(readFileSync(path, "utf8")).autoFallback, true);
  running = true;
  await events.get("before_agent_start")({}, ctx);
  assert.equal(activeURL, "http://127.0.0.1:9999");
  reachable = false;
  await events.get("before_agent_start")({}, ctx);
  assert.equal(activeURL, "https://direct.example", "hung daemon should permit opted-in fallback");
  await commands.get("cover").handler("fallback off", ctx);
  assert.equal(activeURL, "http://127.0.0.1:9999");
  await commands.get("cover").handler("off", ctx);
  reachable = true;
  await events.get("before_agent_start")({}, ctx);
  assert.equal(activeURL, "https://direct.example", "manual off must stay off");
});

test("reconcile retains the last listener on status failure and adopts the recovered listener", async (t) => {
  const oldListener = await startLocalEndpoint(t);
  const recoveredListener = await startLocalEndpoint(t);
  const dir = mkdtempSync(join(tmpdir(), "cover-listener-recovery-"));
  const path = join(dir, "harness.json");
  writeFileSync(path, JSON.stringify({ enabled: true, autoFallback: true, routes: { example: "" } }));

  const registered = new Map(), commands = new Map(), events = new Map();
  let activeURL;
  let currentStatus = { running: true, installed: true, base_url: oldListener.baseURL };
  const pi = {
    registerProvider(name, config) { registered.set(name, config); },
    unregisterProvider(name) { registered.delete(name); },
    registerCommand(name, command) { commands.set(name, command); },
    on(name, handler) { events.set(name, handler); },
    async setModel(model) { activeURL = model.baseUrl; return true; },
  };
  const ctx = {
    model: { provider: "example", id: "test" },
    modelRegistry: { find() { return { provider: "example", id: "test", baseUrl: registered.get("example")?.baseUrl || "https://direct.example" }; } },
    ui: { notify() {}, setStatus() {} },
  };
  createCoverExtension(pi, {
    env: { HOME: dir },
    statePath: path,
    readStatus: () => currentStatus,
  });

  await events.get("before_agent_start")({}, ctx);
  assert.equal(activeURL, oldListener.baseURL);
  assert.equal(oldListener.doctorRequests(), 1);

  currentStatus = {
    running: false,
    installed: true,
    base_url: "http://127.0.0.1:8317",
    error: "status unavailable",
  };
  await events.get("before_agent_start")({}, ctx);
  assert.equal(activeURL, "https://direct.example");

  await commands.get("cover").handler("fallback off", ctx);
  assert.equal(activeURL, oldListener.baseURL, "a failed status read must not replace the last-known listener");
  assert.equal((await fetch(`${activeURL}/provider-request`)).status, 204);
  assert.equal(oldListener.providerRequests(), 1);

  await commands.get("cover").handler("fallback on", ctx);
  oldListener.setHealthy(false);
  currentStatus = { running: true, installed: true, base_url: recoveredListener.baseURL };
  await events.get("before_agent_start")({}, ctx);
  assert.equal(activeURL, recoveredListener.baseURL);
  assert.equal(oldListener.doctorRequests(), 1);
  assert.equal(recoveredListener.doctorRequests(), 1);
});

test("explicit base URL stays authoritative across discovered listener changes", async (t) => {
  const explicitListener = await startLocalEndpoint(t);
  const firstDiscoveredListener = await startLocalEndpoint(t);
  const secondDiscoveredListener = await startLocalEndpoint(t);
  const dir = mkdtempSync(join(tmpdir(), "cover-explicit-listener-"));
  const path = join(dir, "harness.json");
  writeFileSync(path, JSON.stringify({ enabled: true, autoFallback: true, routes: { example: "" } }));

  const registered = new Map(), events = new Map();
  let activeURL;
  let currentStatus = { running: true, installed: true, base_url: firstDiscoveredListener.baseURL };
  const pi = {
    registerProvider(name, config) { registered.set(name, config); },
    unregisterProvider(name) { registered.delete(name); },
    registerCommand() {},
    on(name, handler) { events.set(name, handler); },
    async setModel(model) { activeURL = model.baseUrl; return true; },
  };
  const ctx = {
    model: { provider: "example", id: "test" },
    modelRegistry: { find() { return { provider: "example", id: "test", baseUrl: registered.get("example")?.baseUrl || "https://direct.example" }; } },
    ui: { notify() {}, setStatus() {} },
  };
  createCoverExtension(pi, {
    env: { HOME: dir, COVER_BASE_URL: explicitListener.baseURL },
    statePath: path,
    readStatus: () => currentStatus,
  });

  await events.get("before_agent_start")({}, ctx);
  currentStatus = { running: true, installed: true, base_url: secondDiscoveredListener.baseURL };
  await events.get("before_agent_start")({}, ctx);

  assert.equal(activeURL, explicitListener.baseURL);
  assert.equal(explicitListener.doctorRequests(), 2);
  assert.equal(firstDiscoveredListener.doctorRequests(), 0);
  assert.equal(secondDiscoveredListener.doctorRequests(), 0);
});

test("extension registers routes and persists on/off without touching other providers", async () => {
  const dir = mkdtempSync(join(tmpdir(), "cover-extension-"));
  const path = join(dir, "harness.json");
  const registered = new Map();
  const commands = new Map();
  const events = new Map();
  const notices = [];
  const pi = {
    registerProvider(name, config) { registered.set(name, config); },
    unregisterProvider(name) { registered.delete(name); },
    registerCommand(name, command) { commands.set(name, command); },
    on(name, handler) { events.set(name, handler); },
  };
  const env = {
    HOME: dir,
    COVER_BIN: join(dir, "missing-cover"),
    COVER_BASE_URL: "http://127.0.0.1:9999",
    COVER_PROVIDERS: "openai-codex,deepseek=/",
  };
  createCoverExtension(pi, { env, statePath: path });
  assert.deepEqual(registered.get("openai-codex"), { baseUrl: "http://127.0.0.1:9999/v1" });
  assert.deepEqual(registered.get("deepseek"), { baseUrl: "http://127.0.0.1:9999" });

  const ctx = { ui: { notify(message, level) { notices.push({ message, level }); }, setStatus() {} } };
  await commands.get("cover").handler("off", ctx);
  assert.equal(registered.size, 0);
  assert.equal(JSON.parse(readFileSync(path, "utf8")).enabled, false);
  await commands.get("cover").handler("on", ctx);
  assert.equal(registered.size, 2);
  await events.get("session_start")({}, ctx);
  assert.ok(notices.some(({ message }) => message.includes("binary was not found")));
});
