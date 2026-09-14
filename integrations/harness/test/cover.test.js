import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
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
