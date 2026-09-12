// Exercise the actual detached daemon and CLI against a local mock provider.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, mkdir, writeFile, copyFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import net from "node:net";

const sourceBinary=process.env.COVER_TEST_BINARY;
assert.ok(sourceBinary,"COVER_TEST_BINARY is required");
const root=await mkdtemp(join(tmpdir(),"cover-lifecycle-"));
const binary=join(root,"cover");
await copyFile(sourceBinary,binary);
const env={...process.env,HOME:root,XDG_CONFIG_HOME:join(root,".config"),COVER_NO_BANNER:"1"};
delete env.CODEX_HOME;
const run=async(...args)=> (await promisify(execFile)(binary,args,{env,timeout:15000})).stdout;
let release,arrived;
const entered=new Promise(resolve=>{arrived=resolve;});
const upstream=http.createServer(async(req,res)=>{
 for await(const chunk of req){};
 res.writeHead(200,{"content-type":"text/event-stream"});res.write("data: {}\n\n");
 arrived();await new Promise(resolve=>{release=resolve;});
 res.end("data: [DONE]\n\n");
});
await new Promise(resolve=>upstream.listen(0,"127.0.0.1",resolve));
const probe=net.createServer();await new Promise(resolve=>probe.listen(0,"127.0.0.1",resolve));
const port=probe.address().port;await new Promise(resolve=>probe.close(resolve));
await mkdir(join(root,".config","cover"),{recursive:true});
await writeFile(join(root,".config","cover","config.yaml"),[
 `listen: "127.0.0.1:${port}"`,
 `upstream: "http://127.0.0.1:${upstream.address().port}"`,
 `log_file: "${join(root,"audit.log")}"`,
 "shutdown_timeout_ms: 2000",
].join("\n"));
try {
 await run("start","--detach");
 const before=JSON.parse(await run("status","--json"));assert.ok(before.running);assert.match(before.build_status,/matches/);
 const response=fetch(`http://127.0.0.1:${port}/responses`,{method:"POST",body:JSON.stringify({input:"hello"}),signal:AbortSignal.timeout(10000)}).then(r=>r.text());
 await entered;
 const restart=run("restart");
 setTimeout(()=>release(),150);
 assert.match(await response,/\[DONE\]/,"restart cut off the active response");
 await restart;
 const after=JSON.parse(await run("status","--json"));assert.ok(after.running);assert.notEqual(after.pid,before.pid);
 const doctor=JSON.parse(await run("doctor","--json"));assert.equal(doctor.failed,0);
 const configPath=join(root,".config","cover","config.yaml");
 const beforeConfig=await readFile(configPath,"utf8");
 await copyFile(binary,binary+".previous");
 await run("update","--rollback");
 const rolledBack=JSON.parse(await run("status","--json"));assert.ok(rolledBack.running);assert.notEqual(rolledBack.pid,after.pid);
 assert.equal(await readFile(configPath,"utf8"),beforeConfig,"updater changed configuration");
 await run("stop");assert.equal(JSON.parse(await run("status","--json")).running,false);
 console.log("Detached daemon drained the response, restarted, passed doctor, rolled back without changing config, and stopped.");
} finally {
 release?.();await run("stop").catch(()=>{});await new Promise(resolve=>upstream.close(resolve));
}
