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
