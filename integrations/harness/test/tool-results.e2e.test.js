import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import http from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const enabled = process.env.COVER_HARNESS_E2E === "1";
const httpMCPURL = process.env.COVER_HTTP_MCP_URL;
const agentTimeout = httpMCPURL ? 180000 : 45000;
const extension = resolve(dirname(fileURLToPath(import.meta.url)), "../index.js");
const secrets = { ["password"]: "cedar'private-value", ["client_secret"]: 'maple"private\\value', customer_number: 937165 };
const headerSecret = "birch-private-value";
const cookieSecret = "willow-private-value";

async function listen(server) {
  await new Promise((resolve, reject) => server.listen(0, "127.0.0.1", resolve).once("error", reject));
  return `http://127.0.0.1:${server.address().port}`;
}
async function close(server) {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
async function readBody(request) {
  let body = "";
  for await (const chunk of request) body += chunk;
  return body;
}
async function run(command, args, env, cwd) {
  const child = spawn(command, args, { env, cwd, stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "", stderr = "";
  child.stdout.on("data", chunk => { stdout += chunk; });
  child.stderr.on("data", chunk => { stderr += chunk; });
  const timer = setTimeout(() => child.kill("SIGKILL"), agentTimeout);
  const code = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", resolve);
  });
  clearTimeout(timer);
  assert.equal(code, 0, `${command} failed: ${stderr}\n${stdout}`);
  return stdout;
}
function toolReply(response, tool, args, id) {
  response.writeHead(200, { "Content-Type": "text/event-stream" });
  const base = { id: "chatcmpl-privacy", object: "chat.completion.chunk", model: "fixture", created: 1 };
  const encoded = JSON.stringify(args);
  const fragments = encoded.match(/[\s\S]{1,7}/g) || [""];
  for (const [index, fragment] of fragments.entries()) {
    const call = { index: 0, function: { arguments: fragment } };
    if (index === 0) { call.id = id; call.type = "function"; call.function.name = tool; }
    response.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: { tool_calls: [call] }, finish_reason: null }] })}\n\n`);
  }
  response.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] })}\n\n`);
  response.end("data: [DONE]\n\n");
}
function finalReply(response, content = "privacy round trip verified") {
  response.writeHead(200, { "Content-Type": "text/event-stream" });
  response.write(`data: ${JSON.stringify({ id: "chatcmpl-privacy", object: "chat.completion.chunk", model: "fixture", created: 1, choices: [{ index: 0, delta: { content }, finish_reason: "stop" }] })}\n\n`);
  response.end("data: [DONE]\n\n");
}
function textValues(value) {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(textValues);
  if (value && typeof value === "object") return Object.values(value).flatMap(textValues);
  return [];
}

// These helpers read only this controlled fixture's small HTML vocabulary. The
// production HTML parser is exercised through the real agent/Cover round trip.
function decodeFixtureHTML(text) {
  const entities = { amp: "&", quot: '"', apos: "'", lt: "<", gt: ">", nbsp: "\u00a0" };
  return text.replace(/&(#x[0-9a-f]+|#[0-9]+|amp|quot|apos|lt|gt|nbsp);/gi, (entity, name) => {
    if (!name.startsWith("#")) return entities[name.toLowerCase()];
    const code = name[1].toLowerCase() === "x" ? parseInt(name.slice(2), 16) : Number(name.slice(1));
    return code <= 0x10ffff ? String.fromCodePoint(code) : entity;
  });
}
function escapeFixtureHTML(value) {
  return String(value).replace(/[&<>"'\\]/g, character => `&#${character.codePointAt(0)};`);
}
function fixtureAttributes(tag) {
  const attributes = {};
  for (const match of tag.matchAll(/([^\s=<>/]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g)) {
    attributes[match[1].toLowerCase()] = decodeFixtureHTML(match[2] ?? match[3] ?? match[4]);
  }
  return attributes;
}
function htmlFixture(values) {
  return `<!doctype html><html><head><title>Local privacy fixture</title></head><body>
<form><input value="${escapeFixtureHTML(values["password"])}" name="password">
<input name="confirmation" value="${escapeFixtureHTML(values["client_secret"])}" type="password"></form>
<script id="fixture-data" type="application/json">${JSON.stringify({ customer_number: values.customer_number })}</script>
<p id="reference">${escapeFixtureHTML(values.inline_reference.slice(0, 7))}<em>${escapeFixtureHTML(values.inline_reference.slice(7, 10))}</em>${escapeFixtureHTML(values.inline_reference.slice(10))}</p>
</body></html>`;
}
function readProtectedBody(text) {
  // A transport may wrap both request and response in a non-JSON display.
  // Locate the response and use its framing, not the wrapper's outer braces.
  const responseStart = text.search(/HTTP\/\d(?:\.\d)? [0-9]{3}[^\r\n]*\r?\n/);
  assert.ok(responseStart >= 0, "protected tool result has no HTTP response");
  const response = text.slice(responseStart);
  const separator = /\r?\n\r?\n/.exec(response);
  assert.ok(separator, "protected response has no header/body boundary");
  const length = response.slice(0, separator.index).match(/^Content-Length:\s*(\d+)\s*$/im);
  assert.ok(length, "protected fixture has no Content-Length");
  return Buffer.from(response.slice(separator.index + separator[0].length)).subarray(0, Number(length[1])).toString("utf8");
}
function readProtectedHTML(text) {
  const inputs = [...text.matchAll(/<input\b[^>]*>/gi)].map(match => fixtureAttributes(match[0]));
  const firstValue = inputs.find(input => input.name === "password")?.value;
  const secondValue = inputs.find(input => input.name === "confirmation" && input.type === "password")?.value;
  const script = [...text.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)]
    .find(match => fixtureAttributes(match[1]).type === "application/json");
  assert.ok(script, "protected HTML lost its typed JSON script");
  const customerNumber = JSON.parse(script[2]).customer_number;
  const reference = [...text.matchAll(/<p\b([^>]*)>([\s\S]*?)<\/p\s*>/gi)]
    .find(match => fixtureAttributes(match[1]).id === "reference");
  assert.ok(reference, "protected HTML lost its inline text block");
  const inlineReference = decodeFixtureHTML(reference[2].replace(/<[^>]*>/g, ""));
  assert.equal(typeof customerNumber, "number", "typed JSON number became a string in HTML");
  assert.ok(firstValue && secondValue && inlineReference, "protected HTML is missing fixture values");
  return { ["password"]: firstValue, ["client_secret"]: secondValue, customer_number: customerNumber, inline_reference: inlineReference };
}
function normalizedModelText(value, depth = 0) {
  const values = textValues(value);
  return values.flatMap(text => {
    const normalized = [];
    let current = text;
    for (let encoding = 0; encoding <= 8; encoding++) {
      normalized.push(decodeFixtureHTML(current), decodeFixtureHTML(current.replace(/<[^>]*>/g, "")));
      // Inspect escaped JSON bodies and shell-quoted command history as well as
      // whole JSON strings; decoding is only an independent canary-leak oracle.
      let decoded = current.replace(/'\\''/g, "'").replace(/'"'"'/g, "'");
      decoded = decoded.replace(/\\(?:u[0-9a-f]{4}|["\\/bfnrt])/gi, escape => {
        try { return JSON.parse(`"${escape}"`); } catch { return escape; }
      });
      try { decoded = decodeURIComponent(decoded); } catch { /* Not every text block is URL encoded. */ }
      if (decoded === current) break;
      current = decoded;
    }
    if (depth < 8) {
      try { normalized.push(...normalizedModelText(JSON.parse(text), depth + 1)); } catch { /* Plain text is expected too. */ }
    }
    return normalized;
  });
}

const sources = ["curl", "mcp", ...(httpMCPURL ? ["http-mcp"] : [])];
for (const [source, representation] of sources.flatMap(source => ["JSON", "HTML"].map(representation => [source, representation]))) {
  const representationLabel = representation === "JSON" ? "" : " HTML";
  test(`OMP protects ${source}${representationLabel} HTTP tool output and restores the next executable request`, { skip: !enabled, timeout: agentTimeout + 45000 }, async t => {
    const binary = process.env.COVER_TEST_BINARY;
    assert.ok(binary, "COVER_TEST_BINARY is required");
    if (source === "http-mcp") {
      assert.ok(["127.0.0.1", "localhost", "[::1]"].includes(new URL(httpMCPURL).hostname), "COVER_HTTP_MCP_URL must point to a loopback service");
    }
    const root = await mkdtemp(join(tmpdir(), "cover-tool-result-"));
    const cleanups = [() => rm(root, { recursive: true, force: true })];
    t.after(async () => {
      const errors = [];
      for (const cleanup of cleanups.reverse()) {
        try { await cleanup(); } catch (error) { errors.push(error); }
      }
      if (errors.length) throw new AggregateError(errors, "fixture cleanup failed");
    });
    const verified = [], fetched = [], verifiedHeaders = [], verifiedIDs = [], verifiedForms = [];
    const expectedValues = representation === "HTML"
      ? { ...secrets, ["password"]: `${secrets["password"]}"\\&`, inline_reference: "Case-742981-ZX" }
      : secrets;
    const contentType = representation === "HTML" ? "text/html; charset=utf-8" : "application/json";
    const fixture = http.createServer(async (request, response) => {
      const target = new URL(request.url, "http://localhost");
      if (target.pathname === "/verify-form") {
        verifiedForms.push(Object.fromEntries(new URLSearchParams(await readBody(request))));
        response.writeHead(200, { "Content-Type": "application/json" });
        response.end('{"accepted":true}');
        return;
      }
      if (target.pathname === "/verify") {
        verified.push(JSON.parse(await readBody(request)));
        verifiedHeaders.push({ token: request.headers["x-private-token"], cookie: request.headers.cookie });
        verifiedIDs.push(target.searchParams.get("customer_id"));
        response.writeHead(200, { "Content-Type": "application/json" });
        response.end('{"accepted":true}');
        return;
      }
      fetched.push(request.url);
      const body = representation === "HTML" ? htmlFixture(expectedValues) : JSON.stringify(expectedValues);
      response.writeHead(200, { "Content-Type": contentType, "Content-Length": Buffer.byteLength(body), "X-Private-Token": headerSecret, "Set-Cookie": `session=${cookieSecret}; HttpOnly; Path=/` });
      response.end(body);
    });
    const fixtureURL = await listen(fixture);
    cleanups.push(() => close(fixture));

    // A real SSE MCP transport returning raw HTTP in an MCP text block. The
    // test exercises OMP's MCP client, not a pre-inserted conversation message.
    const sessions = new Map();
    let nextSession = 0, mcpCalls = 0;
    const mcp = http.createServer(async (request, response) => {
      const url = new URL(request.url, "http://localhost");
      if (request.method === "GET") {
        const id = String(++nextSession);
        sessions.set(id, response);
        response.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" });
        response.write(`event: endpoint\ndata: /message?sessionId=${id}\n\n`);
        response.on("close", () => sessions.delete(id));
        return;
      }
      const message = JSON.parse(await readBody(request));
      const stream = sessions.get(url.searchParams.get("sessionId"));
      let result;
      if (message.method === "initialize") result = { protocolVersion: message.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: "privacy-fixture", version: "1.0" } };
      if (message.method === "tools/list") result = { tools: [{ name: "fetch_fixture", description: "Fetch the local synthetic HTTP fixture", inputSchema: { type: "object", properties: {}, additionalProperties: false } }] };
      if (message.method === "tools/call") {
        assert.equal(message.params.name, "fetch_fixture");
        mcpCalls++;
        const fetchedResponse = await fetch(`${fixtureURL}/source`);
        const body = await fetchedResponse.text();
        const raw = `HTTP/1.1 200 OK\r\nContent-Type: ${fetchedResponse.headers.get("content-type")}\r\nContent-Length: ${Buffer.byteLength(body)}\r\nX-Private-Token: ${fetchedResponse.headers.get("x-private-token")}\r\nSet-Cookie: ${fetchedResponse.headers.get("set-cookie")}\r\n\r\n${body}`;
        result = { content: [{ type: "text", text: JSON.stringify({ response: raw }) }], isError: false };
      }
      if (message.id !== undefined) stream.write(`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: message.id, result: result ?? {} })}\n\n`);
      response.writeHead(202); response.end();
    });
    const mcpURL = await listen(mcp);
    cleanups.push(() => close(mcp));

    let stage = 0, providerError, protectedForm;
    const upstream = http.createServer(async (request, response) => {
      if (request.method === "GET" && ["/models", "/v1/models"].includes(request.url)) {
        response.writeHead(200, { "Content-Type": "application/json" });
        response.end(JSON.stringify({ object: "list", data: [{ id: "deepseek-v4-flash", object: "model", created: 1, owned_by: "fixture" }] }));
        return;
      }
      try {
        const raw = await readBody(request);
        const payload = JSON.parse(raw);
        const normalizedText = normalizedModelText(payload);
        for (const secret of [...Object.values(expectedValues), headerSecret, cookieSecret]) {
          if (typeof secret === "number") {
            const originalNumber = new RegExp(`(^|[^0-9])${secret}([^0-9]|$)`);
            assert.ok(!originalNumber.test(raw) && normalizedText.every(text => !originalNumber.test(text)), `upstream received original number at stage ${stage}`);
            continue;
          }
          assert.ok(normalizedText.every(text => !text.includes(secret)), `upstream received a decoded original canary at stage ${stage}`);
          let encoded = secret;
          for (let depth = 0; depth <= 8; depth++) {
            assert.ok(!raw.includes(encoded), `upstream received an original canary at stage ${stage}, encoding depth ${depth}`);
            const next = JSON.stringify(encoded).slice(1, -1);
            if (next === encoded) break;
            encoded = next;
          }
        }
        const toolNames = (payload.tools || []).map(tool => tool.function?.name || tool.name);
        const bash = toolNames.find(name => name === "bash" || name.endsWith("__bash"));
        assert.ok(bash, `missing bash tool: ${toolNames.join(",")}`);
        if (stage++ === 0) {
          if (source === "curl") toolReply(response, bash, { command: `curl --silent --show-error --include '${fixtureURL}/source'` }, "fetch");
          else {
            const tool = toolNames.find(name => name.includes(source === "http-mcp" ? "send_http1_request" : "fetch_fixture"));
            assert.ok(tool, `missing MCP tool: ${toolNames.join(",")}`);
            const target = new URL(fixtureURL);
            const args = source === "http-mcp" ? {
              content: `GET /source HTTP/1.1\r\nHost: ${target.host}\r\nConnection: close\r\n\r\n`,
              targetHostname: target.hostname, targetPort: Number(target.port), usesHttps: false,
            } : {};
            toolReply(response, tool, args, "fetch");
          }
          return;
        }
        if (stage === 2) {
          const lastTool = payload.messages.filter(message => message.role === "tool").at(-1);
          assert.ok(lastTool, "no tool result reached the provider");
          let text = textValues(lastTool.content).join("\n");
          // MCP's text is itself a serialized object containing the HTTP text.
          for (let depth = 0; depth < 4; depth++) {
            try { const decoded = JSON.parse(text); text = typeof decoded === "string" ? decoded : textValues(decoded).join("\n"); } catch { break; }
          }
          const body = readProtectedBody(text);
          const protectedValues = representation === "HTML" ? readProtectedHTML(body) : JSON.parse(body);
          const firstValue = protectedValues["password"];
          const secondValue = protectedValues["client_secret"];
          const customerNumber = protectedValues.customer_number;
          const token = text.match(/X-Private-Token:\s*([^\r\n]+)/i)?.[1];
          const cookie = text.match(/Set-Cookie:\s*session=([^;\r\n]+)/i)?.[1];
          assert.ok(token && cookie, "cannot find protected header and cookie");
          assert.ok(firstValue && secondValue && Number.isInteger(customerNumber), "cannot find protected structured values in tool result");
          protectedForm = Object.fromEntries(Object.entries(protectedValues).map(([name, value]) => [name, String(value)]));
          toolReply(response, bash, { command: `curl --silent --show-error --request POST --header 'Content-Type: application/json' --header 'X-Private-Token: ${token}' --cookie 'session=${cookie}' --data '${JSON.stringify(protectedValues)}' '${fixtureURL}/verify?customer_id=${customerNumber}'` }, "verify");
          return;
        }
        assert.equal(verified.length, 1, "verification request was not executed");
        assert.deepEqual(verified[0], expectedValues, "the agent's next HTTP request did not restore original values and numeric types");
        assert.deepEqual(verifiedHeaders[0], { token: headerSecret, cookie: `session=${cookieSecret}` }, "the executable request did not restore the selected header and cookie");
        assert.equal(verifiedIDs[0], String(secrets.customer_number), "the executable URL did not restore the numeric identifier");
        if (stage === 3) {
          const data = Object.entries(protectedForm).map(([name, value]) => `--data-urlencode '${name}=${value}'`).join(" ");
          toolReply(response, bash, { command: `curl --silent --show-error ${data} '${fixtureURL}/verify-form'` }, "verify-form");
          return;
        }
        assert.deepEqual(verifiedForms, [Object.fromEntries(Object.entries(expectedValues).map(([name, value]) => [name, String(value)]))], "form values did not restore before curl encoded them");
        finalReply(response);
      } catch (error) {
        providerError ||= new Error(`${request.method} ${request.url}, stage ${stage}: ${error.message}`, { cause: error });
        finalReply(response, "fixture validation failed");
      }
    });
    const upstreamURL = await listen(upstream);
    cleanups.push(() => close(upstream));
    const portProbe = http.createServer();
    const coverURL = await listen(portProbe);
    await close(portProbe);
    const coverDir = join(root, ".config", "cover"), agentDir = join(root, "agent");
    await mkdir(coverDir, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    await writeFile(join(coverDir, "config.yaml"), `listen: "${new URL(coverURL).host}"\nupstream: "${upstreamURL}"\nlog_file: "${join(root, "cover.log")}"\nrules:\n  strings:\n    keys: [password, client_secret]\n    action: pseudonymize\n    generator: alias\n  numbers:\n    keys: [customer_number]\n    action: pseudonymize\n    generator: number\n  ids:\n    query_params: [customer_id]\n    action: pseudonymize\n    generator: number\n  headers:\n    headers: [X-Private-Token]\n    action: pseudonymize\n    generator: alias\n  cookies:\n    cookies: [session]\n    action: pseudonymize\n    generator: alias\n`);
    await writeFile(join(coverDir, "config.yaml"), `  form_strings:\n    form_fields: [password, client_secret]\n    action: pseudonymize\n    generator: alias\n  form_numbers:\n    form_fields: [customer_number]\n    action: pseudonymize\n    generator: number\n`, { flag: "a" });
    if (representation === "HTML") {
      await writeFile(join(coverDir, "config.yaml"), `  inline_reference:\n    pattern: 'Case-[0-9]{6}-ZX'\n    action: pseudonymize\n    generator: alias\n`, { flag: "a" });
    }
    await writeFile(join(agentDir, "mcp.json"), JSON.stringify({ mcpServers: source === "curl" ? {} : { fixture: { type: "sse", url: source === "http-mcp" ? httpMCPURL : mcpURL } } }));
    const env = { ...process.env, HOME: root, XDG_CONFIG_HOME: join(root, ".config"), PI_CODING_AGENT_DIR: agentDir, COVER_BIN: binary, COVER_PROVIDERS: "deepseek=/", DEEPSEEK_API_KEY: "test", NO_COLOR: "1" };
    delete env.PI_SESSION_FILE; delete env.PI_ARTIFACTS_DIR; delete env.PI_TOOL_BRIDGE_URL; delete env.PI_TOOL_BRIDGE_SESSION;
    await run(binary, ["start", "--detach"], env, root);
    cleanups.push(() => run(binary, ["stop"], env, root));
    try {
      const output = await run("omp", ["--no-session", "--no-skills", "--no-rules", "--no-title", "--no-extensions", "-e", extension, "--tools", "bash", "--auto-approve", "--system-prompt", "Fetch the synthetic fixture and perform its verification request using the available tools.", "-p", "--model", "deepseek/deepseek-v4-flash", "Run the local privacy check."], env, root);
      if (providerError) throw providerError;
      assert.match(output, /privacy round trip verified/);
      assert.equal(fetched.length, 1);
      assert.equal(verified.length, 1);
      assert.deepEqual(verified[0], expectedValues);
      assert.deepEqual(verifiedHeaders[0], { token: headerSecret, cookie: `session=${cookieSecret}` });
      assert.equal(verifiedIDs[0], String(secrets.customer_number));
      assert.deepEqual(verifiedForms, [Object.fromEntries(Object.entries(expectedValues).map(([name, value]) => [name, String(value)]))]);
      assert.equal(mcpCalls, source === "mcp" ? 1 : 0);
    } catch (error) { throw providerError || error; }
  });
}
