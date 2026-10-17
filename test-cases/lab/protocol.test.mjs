// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { once } from 'node:events';
import { labRoot, loadLab, host, ReplayCache, verifyPinnedMessage } from './fixtures.mjs';
import { digestJson } from '../../dist/index.js';

for (const protocol of ['mcp','a2a']) test(`RT-09 ${protocol}: test host gates real native call and verifies resource-signed result`,{timeout:20000},async()=>{
  const load = createRequire(resolve(labRoot,'package.json'));
  const imported = spec => import(pathToFileURL(load.resolve(spec)).href);
  const {actors}=await loadLab();
  const caller=actors['a2a-a'],target=actors[protocol==='mcp'?'mcp':'a2a-b'];
  const sender=await host(caller,target,protocol),receiver=await host(target,caller,protocol);
  const dir=await mkdtemp(resolve(tmpdir(),'oan-runtime-lab-'));const ledger=resolve(dir,'ledger.jsonl');
  let server,client;
  try {
    // Import actual lab fixture implementation. A missing build is an actionable failure.
    const module=await import(pathToFileURL(resolve(labRoot,`dist/src/agents/${protocol}.js`)).href);
    const app=protocol==='mcp'?module.createMcpApp({instance:'mcp',ledger}):module.createA2aApp({instance:'a2a-b',ledger,publicUrl:'http://127.0.0.1/'});
    server=app.listen(0,'127.0.0.1');await once(server,'listening');
    const url=`http://127.0.0.1:${server.address().port}`;
    // Ephemeral listener avoids deployment ports; registered endpoint is checked separately.
    if(protocol==='a2a') {
      // Agent Card must advertise the actual ephemeral JSON-RPC address.
      await new Promise((yes,no)=>server.close(error=>error?no(error):yes()));
      const app2=module.createA2aApp({instance:'a2a-b',ledger,publicUrl:url});
      server=app2.listen(Number(new URL(url).port),'127.0.0.1');await once(server,'listening');
    }
    const count=async()=>{try{return (await readFile(ledger,'utf8')).trim().split('\n').filter(Boolean).length;}catch(e){if(e.code==='ENOENT')return 0;throw e;}};
    let invoke;
    if(protocol==='mcp') {
      const {Client}=await imported('@modelcontextprotocol/sdk/client/index.js');
      const {StreamableHTTPClientTransport}=await imported('@modelcontextprotocol/sdk/client/streamableHttp.js');
      client=new Client({name:'oan-runtime-lab',version:'0.1.0'});
      await client.connect(new StreamableHTTPClientTransport(new URL(url+'/mcp')));
      invoke=async value=>{const result=await client.callTool({name:'record',arguments:{value}});assert.ok(!result.isError);return result;};
    } else {
      const {ClientFactory}=await imported('@a2a-js/sdk/client');const {Role,TaskState}=await imported('@a2a-js/sdk');
      const a2a=await new ClientFactory().createFromUrl(url);
      invoke=async value=>{const result=await a2a.sendMessage({tenant:'',metadata:{},configuration:undefined,message:{role:Role.ROLE_USER,messageId:crypto.randomUUID(),contextId:'',taskId:'',extensions:[],metadata:{},referenceTaskIds:[],parts:[{content:{$case:'text',value:'record:'+value},mediaType:'text/plain',filename:'',metadata:undefined}]}});assert.equal(result.status.state,TaskState.TASK_STATE_COMPLETED);return JSON.parse(JSON.stringify(result));};
    }
    const replay=new ReplayCache();
    const gated=async message=>{await verifyPinnedMessage(message,{...sender.pinned,replay});return invoke(message.payload.value);};
    const signed=await sender.runtime.signIntent(sender.caller,{...sender.intent,payload:{value:'runtime-native-positive'}});
    const tampered=structuredClone(signed);tampered.payload.value='tampered';
    await assert.rejects(gated(tampered),/payload_digest_mismatch/);assert.equal(await count(),0);
    const result=await gated(signed);assert.equal(await count(),1);
    await assert.rejects(gated(signed),/replay_detected/);assert.equal(await count(),1);
    const requestDigest=await digestJson(signed);
    const response=await receiver.runtime.signIntent(receiver.caller,{...receiver.intent,purpose:'response',serviceRef:sender.intent.serviceRef,requestDigest,payload:result});
    const expected={...receiver.pinned,purpose:'response',serviceRef:sender.intent.serviceRef,requestDigest};
    await verifyPinnedMessage(response,expected);
    const altered=structuredClone(response);altered.payload={result:'substituted'};
    await assert.rejects(verifyPinnedMessage(altered,{...expected,replay:new ReplayCache()}),/payload_digest_mismatch/);
    assert.equal(await count(),1);
    // Expose the remaining gap: a direct native call STILL bypasses this test-only gate.
    await invoke('native-bypass-demonstration');assert.equal(await count(),2);
  } finally {
    try {await client?.close();} finally {
      try {if(server?.listening)await new Promise((yes,no)=>{server.close(error=>error?no(error):yes());server.closeAllConnections();});} finally {await rm(dir,{recursive:true,force:true});}
    }
  }
});
