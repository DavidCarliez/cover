import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const enabled = process.env.COVER_HARNESS_E2E === "1";
const here = dirname(fileURLToPath(import.meta.url));
const extension = resolve(here, "../index.js");
const secret = "customer-secret@example.com";

async function freePort() {
  const server = net.createServer();
  await new Promise((resolveListen, reject) => server.listen(0, "127.0.0.1", resolveListen).once("error", reject));
  const { port } = server.address();
  await new Promise((resolveClose) => server.close(resolveClose));
  return port;
}

async function waitForPort(port, timeout = 10000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const open = await new Promise((resolveOpen) => {
      const socket = net.createConnection({ host: "127.0.0.1", port });
      socket.once("connect", () => { socket.destroy(); resolveOpen(true); });
      socket.once("error", () => resolveOpen(false));
    });
    if (open) return;
    await new Promise((resolveWait) => setTimeout(resolveWait, 50));
  }
  throw new Error(`port ${port} did not open`);
}

async function run(command, args, env, cwd) {
  const child = spawn(command, args, { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const timer = setTimeout(() => child.kill("SIGTERM"), 30000);
  const code = await new Promise((resolveExit, reject) => {
    child.once("error", reject);
    child.once("exit", resolveExit);
  });
  clearTimeout(timer);
  assert.equal(code, 0, `${command} failed\nstdout:\n${stdout}\nstderr:\n${stderr}`);
  return `${stdout}${stderr}`;
}

test("Pi and OMP send protected values through Cover and receive restored output", { skip: !enabled, timeout: 90000 }, async (t) => {
  const coverBinary = process.env.COVER_TEST_BINARY;
  assert.ok(coverBinary, "COVER_TEST_BINARY must point to a built Cover binary");
  const root = mkdtempSync(join(tmpdir(), "cover-harness-e2e-"));
  const upstreamPort = await freePort();
  const coverPort = await freePort();
  const received = [];

  const upstream = http.createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;
    received.push(body);
    const match = body.match(/Repeat this exact value:\s*([^"\\\s]+)/);
    const protectedValue = match?.[1] || "protected-value";
    response.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache",
      connection: "keep-alive",
    });
    const base = { id: "chatcmpl-cover", object: "chat.completion.chunk", created: 1, model: "fake" };
    response.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: { role: "assistant", content: protectedValue }, finish_reason: null }] })}\n\n`);
    response.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } })}\n\n`);
    response.end("data: [DONE]\n\n");
  });
  await new Promise((resolveListen, reject) => upstream.listen(upstreamPort, "127.0.0.1", resolveListen).once("error", reject));
  t.after(() => upstream.close());

  const coverDir = join(root, ".config", "cover");
  mkdirSync(coverDir, { recursive: true });
  writeFileSync(join(coverDir, "config.yaml"), [
    `listen: "127.0.0.1:${coverPort}"`,
    `upstream: "http://127.0.0.1:${upstreamPort}/v1"`,
    `log_file: "${join(root, "cover.log")}"`,
    "rules:",
    "  customer_email:",
    "    pattern: '(?i)customer-secret@example\\.com'",
    "    category: customer",
    "    action: pseudonymize",
    "    generator: email",
    "    priority: 300",
    "",
  ].join("\n"), { mode: 0o600 });

  const commonEnv = {
    ...process.env,
    HOME: root,
    XDG_CONFIG_HOME: join(root, ".config"),
    COVER_BIN: coverBinary,
    COVER_PROVIDERS: "deepseek=/",
    DEEPSEEK_API_KEY: "test",
    NO_COLOR: "1",
  };
  const cover = spawn(coverBinary, ["start"], { env: commonEnv, stdio: ["ignore", "pipe", "pipe"] });
  let coverError = "";
  cover.stderr.on("data", (chunk) => { coverError += chunk; });
  t.after(() => cover.kill("SIGTERM"));
  await waitForPort(coverPort).catch((error) => { throw new Error(`${error.message}: ${coverError}`); });

  const piAgent = join(root, "pi-agent");
  mkdirSync(piAgent, { recursive: true });
  const piOutput = await run("pi", ["-e", extension, "--no-session", "--no-tools", "-p", "--provider", "deepseek", "--model", "deepseek-v4-flash", `Repeat this exact value: ${secret}`], {
    ...commonEnv,
    PI_CODING_AGENT_DIR: piAgent,
  }, root);
  assert.match(piOutput, new RegExp(secret.replace(".", "\\.")), `Pi did not receive the restored value: ${piOutput}`);

  const ompAgent = join(root, "omp-agent");
  mkdirSync(ompAgent, { recursive: true });
  const ompOutput = await run("omp", ["-e", extension, "--no-session", "--no-tools", "--no-title", "-p", "--model", "deepseek/deepseek-v4-flash", `Repeat this exact value: ${secret}`], {
    ...commonEnv,
    PI_CODING_AGENT_DIR: ompAgent,
  }, root);
  assert.match(ompOutput, new RegExp(secret.replace(".", "\\.")), `OMP did not receive the restored value: ${ompOutput}`);
  assert.ok(received.length >= 2, `expected requests from both harnesses, received ${received.length}`);
  assert.ok(received.every((body) => !body.includes(secret)), "an upstream request contained the original secret");
});
