// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import test from 'node:test';
import assert from 'node:assert/strict';
import {connect} from 'node:net';
import {randomUUID} from 'node:crypto';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createVerifyIpc} from '../src/host/verify-ipc.js';

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
