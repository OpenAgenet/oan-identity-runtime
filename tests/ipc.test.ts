// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import test from 'node:test';
import assert from 'node:assert/strict';
import {connect} from 'node:net';
import {randomUUID} from 'node:crypto';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createVerifyIpc, createAuthenticatedRuntimeIpc, listenAuthenticatedRuntimeIpc} from '../src/host/verify-ipc.js';

test('SEC-02: IPC rejects unauthenticated callers before verifier and never reflects secret exception text',async()=>{
  const token=randomUUID()+randomUUID(),endpoint=process.platform==='win32'?'\\\\.\\pipe\\oan-test-'+randomUUID():join(tmpdir(),'oan-'+randomUUID()+'.sock');
  let calls=0;const server=createVerifyIpc(token,async()=>{calls++;throw new Error('secret-token-should-never-escape');});
  await new Promise<void>((resolve,reject)=>{server.once('error',reject);server.listen(endpoint,resolve);});
  const request=(supplied:string)=>new Promise<any>((resolve,reject)=>{
    const socket=connect(endpoint);let output='';socket.setTimeout(5000,()=>socket.destroy(new Error('timeout')));
    socket.on('error',reject);socket.on('connect',()=>socket.write(JSON.stringify({version:1,id:'request',operation:'verify',token:supplied,message:{test:true}})+'\n'));
    socket.on('data',data=>output+=data.toString('utf8'));socket.on('end',()=>resolve(JSON.parse(output)));
  });
  try{
    assert.equal((await request('invalid')).code,'ipc_unauthorized');assert.equal(calls,0);
    const result=await request(token);assert.equal(result.code,'ipc_verification_failed');assert.equal(calls,1);
    assert(!JSON.stringify(result).includes('secret-token'));
  }finally{await new Promise<void>((resolve,reject)=>server.close(error=>error?reject(error):resolve()));}
});

test('SEC-02: IPC enforces token length, schema, byte limit and single-request framing',async()=>{
  assert.throws(()=>createVerifyIpc('short',async()=>({})),/ipc_token_too_short/);
  const token=randomUUID()+randomUUID(),endpoint=process.platform==='win32'?'\\\\.\\pipe\\oan-test-'+randomUUID():join(tmpdir(),'oan-'+randomUUID()+'.sock');
  let calls=0;const server=createVerifyIpc(token,async message=>{calls++;return {accepted:message};});
  await new Promise<void>((resolve,reject)=>{server.once('error',reject);server.listen(endpoint,resolve);});
  const request=(data:string)=>new Promise<any>((resolve,reject)=>{
    const socket=connect(endpoint);let output='';socket.setTimeout(5000,()=>socket.destroy(new Error('timeout')));
    socket.on('error',reject);socket.on('connect',()=>socket.write(data));
    socket.on('data',part=>output+=part.toString('utf8'));socket.on('end',()=>resolve(JSON.parse(output)));
  });
  const valid={version:1,id:'request',operation:'verify',token,message:{public:'payload'}};
  try{
    for(const change of [{version:2},{operation:'sign'},{id:'x'.repeat(129)}]){
      assert.equal((await request(JSON.stringify({...valid,...change})+'\n')).code,'ipc_schema_invalid');
    }
    assert.equal((await request('{broken json\n')).code,'ipc_verification_failed');
    assert.equal((await request('x'.repeat(131073)+'\n')).code,'ipc_size_limit');
    assert.equal(calls,0);
    const result=await request(JSON.stringify(valid)+'\n');
    assert.equal(result.ok,true);assert.match(result.inputDigest,/^sha256:[0-9a-f]{64}$/);
    assert.deepEqual(result.result,{accepted:valid.message});assert.equal(calls,1);
    const multiple=await request(JSON.stringify(valid)+'\n'+JSON.stringify(valid)+'\n');
    assert.equal(multiple.ok,false);assert.equal(calls,1);
  }finally{await new Promise<void>((resolve,reject)=>server.close(error=>error?reject(error):resolve()));}
});

test('G5: authenticated Runtime IPC binds callback and caller context', async () => {
  const token = randomUUID() + randomUUID(), endpoint = process.platform === 'win32' ? `\\\\.\\pipe\\oan-callback-${randomUUID()}` : join(tmpdir(), `oan-callback-${randomUUID()}.sock`);
  const server = createAuthenticatedRuntimeIpc({ token, callerId: 'sidecar-a', tenantId: 'tenant-a', verify: async input => ({ subjectDid: 'did:oan:caller', audienceDid: input.audience, requestId: input.requestId, payloadDigest: input.payloadDigest, callbackDid: input.callbackDid }) });
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(endpoint, resolve); });
  const request = (callbackDid?: string) => new Promise<any>((resolve, reject) => {
    const socket = connect(endpoint); let output = ''; socket.on('error', reject); socket.on('connect', () => socket.write(JSON.stringify({ version: 'oan-runtime-ipc-v1', operation: callbackDid ? 'verify_callback' : 'verify_request', bearer: token, envelope: { signed: true }, expectedAudience: 'did:oan:target', expectedRequestId: 'req-1', expectedPayloadDigest: 'sha256:' + '1'.repeat(64), ...(callbackDid ? { callbackDid } : {}) }) + '\n')); socket.on('data', part => output += part.toString('utf8')); socket.on('end', () => resolve(JSON.parse(output)));
  });
  try { const result = await request('did:oan:caller'); assert.equal(result.callerId, 'sidecar-a'); assert.equal(result.context.callbackDid, 'did:oan:caller'); assert.equal(result.context.tenantId, 'tenant-a'); }
  finally { await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())); }
});

test('G5: authenticated Runtime IPC binds outbound signing intent and rejects caller substitution', async () => {
  const token = randomUUID() + randomUUID(), endpoint = process.platform === 'win32' ? `\\\\.\\pipe\\oan-sign-${randomUUID()}` : join(tmpdir(), `oan-sign-${randomUUID()}.sock`);
  const server = createAuthenticatedRuntimeIpc({ token, callerId: 'sidecar-a', tenantId: 'tenant-a', verify: async input => ({ subjectDid: 'did:oan:caller', audienceDid: input.audience, requestId: input.requestId, payloadDigest: input.payloadDigest }), sign: async intent => ({ envelope: { intent, signedBy: 'did:oan:caller' } }) });
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(endpoint, resolve); });
  const request = (callerId = 'sidecar-a') => new Promise<any>((resolve, reject) => {
    const socket = connect(endpoint); let output = ''; socket.on('error', reject); socket.on('connect', () => socket.write(JSON.stringify({ version: 'oan-runtime-ipc-v1', operation: 'sign_request', bearer: token, intent: { method: 'POST', target: '/record' }, expectedCallerId: callerId, expectedTenantId: 'tenant-a' }) + '\n')); socket.on('data', part => output += part.toString('utf8')); socket.on('end', () => resolve(JSON.parse(output)));
  });
  try { assert.equal((await request()).callerId, 'sidecar-a'); assert.equal((await request('forged')).code, 'ipc_schema_invalid'); }
  finally { await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())); }
});

test('G5: authenticated Runtime IPC rejects multiple request frames and redacts backend exceptions', async () => {
  const token = randomUUID() + randomUUID(), endpoint = process.platform === 'win32' ? `\\\\.\\pipe\\oan-frame-${randomUUID()}` : join(tmpdir(), `oan-frame-${randomUUID()}.sock`);
  let effects = 0;
  const server = createAuthenticatedRuntimeIpc({ token, callerId: 'gateway-a', verify: async () => { effects++; throw new Error('secret-backend-detail'); } });
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(endpoint, resolve); });
  const frame = JSON.stringify({ version: 'oan-runtime-ipc-v1', operation: 'verify_request', bearer: token, envelope: {}, expectedAudience: 'did:oan:target', expectedRequestId: 'req', expectedPayloadDigest: 'sha256:x' }) + '\n';
  const request = (bytes: string) => new Promise<any>((resolve, reject) => { const socket = connect(endpoint); let output = ''; socket.on('error', reject); socket.on('connect', () => socket.write(bytes)); socket.on('data', part => output += part.toString('utf8')); socket.on('end', () => resolve(JSON.parse(output))); });
  try {
    assert.equal((await request(frame + frame)).code, 'ipc_schema_invalid'); assert.equal(effects, 0);
    const result = await request(frame); assert.equal(result.code, 'runtime_verification_failed'); assert.equal(effects, 1);
    assert.equal(JSON.stringify(result).includes('secret-backend-detail'), false);
  } finally { await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())); }
});

test('G5: authenticated Runtime IPC local listener rejects arbitrary endpoints and serves its pipe', async () => {
  const token = randomUUID() + randomUUID(), endpoint = process.platform === 'win32' ? `\\\\.\\pipe\\oan-listener-${randomUUID()}` : join(tmpdir(), `oan-listener-${randomUUID()}.sock`);
  const server = createAuthenticatedRuntimeIpc({ token, callerId: 'gateway-a', verify: async input => ({ subjectDid: 'did:oan:caller', audienceDid: input.audience, requestId: input.requestId, payloadDigest: input.payloadDigest }) });
  await assert.rejects(listenAuthenticatedRuntimeIpc(server, '127.0.0.1:1234'), /runtime_ipc_endpoint_invalid/);
  await listenAuthenticatedRuntimeIpc(server, endpoint);
  try {
    const response = await new Promise<any>((resolve, reject) => { const socket = connect(endpoint); let output = ''; socket.on('error', reject); socket.on('connect', () => socket.write(JSON.stringify({ version: 'oan-runtime-ipc-v1', operation: 'verify_request', bearer: token, envelope: {}, expectedAudience: 'did:oan:target', expectedRequestId: 'req', expectedPayloadDigest: 'sha256:x' }) + '\n')); socket.on('data', part => output += part.toString('utf8')); socket.on('end', () => resolve(JSON.parse(output))); });
    assert.equal(response.callerId, 'gateway-a'); assert.equal(response.context.subjectDid, 'did:oan:caller');
  } finally { await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())); }
});
