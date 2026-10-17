// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createOanIdentityRecord,signDidDocumentProof} from '@openagenet/oan-sdk-ts';
import {SqliteBlobStore} from '../src/store/sqlite.js';
import {DurableIdentityVerification,EncryptedKeyProvider,IdentityCatalog,MemoryAuditSink,IdentityRuntime,PolicyEngine,
  SynchronousInvocation,SqliteReplayStore,digestJson,RuntimeToolHost,ResourceDirectory,attachOanMetadata,detachOanMetadata,NativeSynchronousBoundary,httpRequestObject,protectA2aHandler,a2aRequestObject,a2aResultObject} from '../src/index.js';

const caller={callerId:'test-owner',tenantId:'tenant-a'};
async function pair(){
  const identities=await Promise.all(['a','b'].map(async label=>{
    const i=await createOanIdentityRecord({label,kind:'agent',resourceType:'skill'});i.didDocument=await signDidDocumentProof(i.didDocument,i);return i;
  }));
  let revision='original',available=true;
  const resolvePeer=async(did:string)=>{
    if(!available)throw new Error('evidence unavailable');const i=identities.find(i=>i.did===did);if(!i)throw new Error('unknown');
    return {did,verificationMethod:i.verificationMethodId,publicKeyJwk:i.publicKeyJwk as JsonWebKey,validUntil:Date.now()+120000,evidenceBinding:revision};
  };
  const sides=await Promise.all(identities.map(async(identity,index)=>{
    const store=new SqliteBlobStore(':memory:'),master=randomBytes(32),keys=new EncryptedKeyProvider(store);keys.unlock(master);
    await keys.importJwk('resource-key',identity.verificationMethodId,identity.privateKeyJwk as JsonWebKey);
    const catalog=new IdentityCatalog();await catalog.add({id:'resource',did:identity.did,kind:'resource',status:'registered',verificationMethodId:identity.verificationMethodId,keyRef:'resource-key',didDocument:identity.didDocument,evidenceRefs:['verified']});
    const other=identities[1-index],audit=new MemoryAuditSink();
    const options={store:keys,catalog,keys:{resolve:()=>keys.getSigner('resource-key')},audit,resolvePeer,
      async authorize(c:{callerId:string;tenantId?:string},input:any){if(c.callerId!==caller.callerId || c.tenantId!==caller.tenantId || input.identityRef!=='resource' || input.peerDid!==other.did)throw new Error('policy_denied');}};
    let workflow=new DurableIdentityVerification(options);
    const runtime=new IdentityRuntime({catalog,keys:options.keys,audit,sessions:{requireAuthenticated:(...args)=>workflow.requireAuthenticated(...args)},
      policy:new PolicyEngine(['request','response'].map(purpose=>({callerId:caller.callerId,tenantId:caller.tenantId,identityRef:'resource',audienceDid:other.did,purpose:purpose as 'request'|'response',protocol:'mcp',operation:'tools/call:echo'})))});
    const replay=new SqliteReplayStore(':memory:');
    const invocation=new SynchronousInvocation({identityRef:'resource',localDid:identity.did,peerDid:other.did,runtime,sessions:workflow,replay,resolvePeer,journal:keys,
      profile:{protocol:'mcp',protocolVersion:'2025-11-25',serviceRef:identities[1].did+'#mcp',operation:'tools/call:echo',descriptorDigest:await digestJson({tools:['echo']})},
      async authorize(c){if(c.tenantId!==caller.tenantId)throw new Error('policy_denied');}});
    return {identity,keys,master,options,invocation,get workflow(){return workflow;},restart(){workflow=new DurableIdentityVerification(options);},
      input:{identityRef:'resource',peerDid:other.did,purpose:'mutual-identity',scope:'integration',profile:'oan-session-v1' as const,protocol:'mcp' as const,protocolVersion:'2025-11-25',serviceRef:identities[1].did+'#mcp'},
      close(){replay.close();keys.lock();store.close();}};
  }));
  return {a:sides[0],b:sides[1],changeEvidence(){revision='changed';},unavailable(){available=false;},close(){sides.forEach(s=>s.close());}};
}
async function handshake(p:Awaited<ReturnType<typeof pair>>){
  const h=await p.a.workflow.begin(caller,p.a.input),s=await p.b.workflow.accept(caller,p.b.input,h.outgoing);
  const cp=await p.a.workflow.advance(caller,h.sessionRef,s.outgoing),cf=await p.b.workflow.advance(caller,s.sessionRef,cp.outgoing!);
  await p.a.workflow.advance(caller,h.sessionRef,cf.outgoing!);return {h,s,cp,cf};
}
test('G3: durable four-message handshake resumes, requires final confirmation and closes without replay reset',async()=>{
  const p=await pair();try{
    const h=await p.a.workflow.begin(caller,p.a.input);p.a.restart();
    assert.deepEqual((await p.a.workflow.inspect(caller,h.sessionRef)).outgoing,h.outgoing);
    const s=await p.b.workflow.accept(caller,p.b.input,h.outgoing);p.b.restart();
    const cp=await p.a.workflow.advance(caller,h.sessionRef,s.outgoing);p.a.restart();
    const cf=await p.b.workflow.advance(caller,h.sessionRef,cp.outgoing!);p.b.restart();
    assert.equal((await p.a.workflow.inspect(caller,h.sessionRef)).state,'pending');
    await assert.rejects(p.a.workflow.requireAuthenticated(h.sessionRef,p.a.identity.did,p.b.identity.did),/session_not_authenticated/);
    const resend=await p.b.workflow.advance(caller,h.sessionRef,cp.outgoing!);assert.deepEqual(resend.outgoing,cf.outgoing);
    await p.a.workflow.advance(caller,h.sessionRef,resend.outgoing!);p.a.restart();
    assert.equal((await p.a.workflow.inspect(caller,h.sessionRef)).state,'completed');
    assert.equal((await p.a.workflow.advance(caller,h.sessionRef,resend.outgoing!)).status.state,'completed');
    await p.b.workflow.close(caller,h.sessionRef);
    assert.equal((await p.b.workflow.inspect(caller,h.sessionRef)).state,'closed');
    await assert.rejects(p.b.workflow.accept(caller,p.b.input,h.outgoing),/generation_conflict/);
  }finally{p.close();}
});

test('G4 native boundary normalizes empty metadata, preserves other metadata and rejects descriptor/request swaps',async()=>{
  const p=await pair();try{
    const {h}=await handshake(p),a=new NativeSynchronousBoundary(p.a.invocation,caller,'_meta'),b=new NativeSynchronousBoundary(p.b.invocation,caller,'_meta');
    let effects=0;
    const result=await a.call(h.sessionRef,'native',{name:'echo',arguments:{text:'one'},_meta:{}},actual=>b.handle(actual,async()=>{
      effects++;return {content:[{type:'text',text:'ok'}],_meta:{native:'retained'}};
    }));
    assert.equal(effects,1);assert.deepEqual(result._meta,{native:'retained'});
    await assert.rejects(b.handle({name:'echo',arguments:{text:'bypass'}},async()=>{effects++;return {};}),/protection_required/);
    const object={name:'echo',arguments:{text:'two'}},request=await p.a.invocation.prepare(caller,h.sessionRef,'second',object);
    const response=await p.b.invocation.receive(caller,request,object,async()=>({isError:true,content:[]}));
    const swapped=await p.a.invocation.prepare(caller,h.sessionRef,'other',object);
    await assert.rejects(p.a.invocation.acceptResponse(caller,swapped,response));
    assert.equal((await p.a.invocation.acceptResponse(caller,request,response)).registrationTrust,'verified_pinned_root');
    assert.equal(effects,1);
  }finally{p.close();}
});

test('G4 HTTP object preserves raw bytes, target and header order and rejects lossy values',async()=>{
  const request=httpRequestObject({method:'POST',target:'/record?a=1&a=2',headers:[['x-native','a'],['x-native','b']],body:Buffer.from([0,255,10])});
  assert.equal(request.bodyBase64,'AP8K');assert.equal(request.target,'/record?a=1&a=2');assert.equal(request.headers.length,2);
  assert.throws(()=>httpRequestObject({method:'post',target:'/',headers:[],body:new Uint8Array()}),/invalid_http_object/);
});

test('G4 A2A product mapping keeps Message results and denies unsupported native entrypoints before execution',async()=>{
  assert.equal(a2aRequestObject({message:{messageId:'a',role:'ROLE_USER',parts:[{text:'hello'}]}}).message!==undefined,true);
  assert.equal(a2aResultObject({messageId:'reply',role:'ROLE_AGENT',parts:[{text:'result'}]}).messageId,'reply');
  let executions=0;
  const native={async sendMessage(){executions++;return {messageId:'reply'};},async getAgentCard(){return {name:'public'};}};
  const wrapped=protectA2aHandler(native as any,{async handle(input:any,handler:any){return handler(input);}} as any);
  await assert.rejects(wrapped.sendMessage({configuration:{returnImmediately:true}} as any,{} as any),/protected_async_operation_unsupported/);
  for(const operation of ['getTask','sendMessageStream','createTaskPushNotificationConfig','getAuthenticatedExtendedAgentCard']){
    assert.throws(()=>(wrapped as any)[operation]({},{}),/protected_operation_unsupported/);
  }
  assert.equal(executions,0);assert.equal((await wrapped.getAgentCard()).name,'public');
});
test('G3: caller/tenant isolation, altered purpose, reflection, invalid signature and concurrency fail closed',async()=>{
  const p=await pair();try{
    const h=await p.a.workflow.begin(caller,p.a.input);
    await assert.rejects(p.a.workflow.inspect({...caller,tenantId:'other'},h.sessionRef),/session_access_denied/);
    await assert.rejects(p.a.workflow.requireAuthenticatedForCaller({...caller,callerId:'another-permitted-user'},h.sessionRef,p.a.identity.did,p.b.identity.did),/session_access_denied/);
    await assert.rejects(p.b.workflow.accept(caller,{...p.b.input,purpose:'unapproved'},h.outgoing),/handshake_binding_invalid/);
    const bad=structuredClone(h.outgoing);bad.jws=bad.jws.slice(0,-5)+'AAAAA';
    await assert.rejects(p.b.workflow.accept(caller,p.b.input,bad),/handshake_signature_invalid/);
    const s=await p.b.workflow.accept(caller,p.b.input,h.outgoing);
    await assert.rejects(p.a.workflow.advance(caller,h.sessionRef,h.outgoing),/handshake_binding_invalid/);
    const results=await Promise.allSettled([p.a.workflow.advance(caller,h.sessionRef,s.outgoing),p.a.workflow.advance(caller,h.sessionRef,s.outgoing)]);
    assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
  }finally{p.close();}
});
test('G3: evidence revision invalidates recovered sessions and locked vault denies reads and signing',async()=>{
  const p=await pair();try{
    const {h}=await handshake(p);p.changeEvidence();
    await assert.rejects(p.a.workflow.inspect(caller,h.sessionRef),/session_evidence_changed/);
    p.a.keys.lock();await assert.rejects(p.a.workflow.inspect(caller,h.sessionRef),/vault_locked/);
  }finally{p.close();}
});
test('G3: closed sessions retain a tombstone, old transcripts cannot re-enter, and unavailable evidence fails closed',async()=>{
  const p=await pair();try{
    const h=await p.a.workflow.begin(caller,p.a.input);
    await p.b.workflow.accept(caller,p.b.input,h.outgoing);
    await p.a.workflow.close(caller,h.sessionRef);
    await p.b.workflow.close(caller,h.sessionRef);
    assert.equal((await p.a.workflow.inspect(caller,h.sessionRef)).state,'closed');
    await assert.rejects(p.a.workflow.advance(caller,h.sessionRef,h.outgoing),/session_closed/);
    await assert.rejects(p.b.workflow.accept(caller,p.b.input,h.outgoing),/generation_conflict/);
    const q=await pair();try{
      const pending=await q.a.workflow.begin(caller,q.a.input);q.unavailable();
      await assert.rejects(q.a.workflow.inspect(caller,pending.sessionRef),/evidence unavailable/);
    }finally{q.close();}
  }finally{p.close();}
});
test('G3: public handshake input rejects private material, oversized messages, and malformed envelopes',async()=>{
  const p=await pair();try{
    const h=await p.a.workflow.begin(caller,p.a.input);
    const privateMessage=structuredClone(h.outgoing) as any;privateMessage.body={...(privateMessage.body as Record<string,unknown>),privateKeyJwk:{d:'secret'}};
    await assert.rejects(p.b.workflow.accept(caller,p.b.input,privateMessage),/invalid_handshake_message/);
    await assert.rejects(p.b.workflow.accept(caller,p.b.input,{...h.outgoing,jws:h.outgoing.jws+'x'.repeat(20000)} as any),/invalid_handshake_message|handshake_too_large/);
    await assert.rejects(p.b.workflow.accept(caller,p.b.input,{...h.outgoing,extra:'spoof'} as any),/invalid_handshake_message/);
  }finally{p.close();}
});
test('G4: actual request/result binding, nonce protection and independent operation journal gate handler effects',async()=>{
  const p=await pair();let effects=0;try{
    const {h}=await handshake(p),object={name:'echo',arguments:{text:'one'}};
    const request=await p.a.invocation.prepare(caller,h.sessionRef,'one',object);
    const bad=structuredClone(request);bad.signature.value=bad.signature.value.slice(0,-5)+'AAAAA';
    await assert.rejects(p.b.invocation.receive(caller,bad,object,async()=>++effects));
    const result=await p.b.invocation.receive(caller,request,object,async()=>{effects++;return {content:[{type:'text',text:'ok'}]};});
    assert.equal(effects,1);await p.a.invocation.acceptResponse(caller,request,result);
    await assert.rejects(p.b.invocation.receive(caller,request,object,async()=>++effects),/replay_detected/);
    const retry=await p.a.invocation.prepare(caller,h.sessionRef,'one',object);
    await assert.rejects(p.b.invocation.receive(caller,retry,object,async()=>++effects),/operation_already_submitted/);
    const changed=await p.a.invocation.prepare(caller,h.sessionRef,'one',{name:'echo',arguments:{text:'two'}});
    await assert.rejects(p.b.invocation.receive(caller,changed,{name:'echo',arguments:{text:'two'}},async()=>++effects),/operation_id_conflict/);
    assert.equal((await p.b.invocation.inspect(caller,'one')).state,'completed');
    assert.equal(effects,1);
  }finally{p.close();}
});
test('G4: response tampering/correlation and unknown dispatch never expose trusted output or auto retry',async()=>{
  const p=await pair();try{
    const {h}=await handshake(p),object={name:'echo',arguments:{text:'one'}};
    const request=await p.a.invocation.prepare(caller,h.sessionRef,'one',object);
    const result=await p.b.invocation.receive(caller,request,object,async()=>({isError:true,content:[{type:'text',text:'native error'}]}));
    const tampered=structuredClone(result);tampered.result={content:[{type:'text',text:'tampered'}]};
    await assert.rejects(p.a.invocation.acceptResponse(caller,request,tampered),/invocation_binding/);
    assert.deepEqual((await p.a.invocation.acceptResponse(caller,request,result)).result,result.result);
    let calls=0;await assert.rejects(p.a.invocation.execute(caller,{sessionRef:h.sessionRef,payload:object},async()=>{calls++;throw new Error('response lost');}),/invocation_result_unknown/);assert.equal(calls,1);
  }finally{p.close();}
});
test('G4: native metadata collisions and invocation journal access fail closed',async()=>{
  const p=await pair();try{
    const {h}=await handshake(p),a=new NativeSynchronousBoundary(p.a.invocation,caller,'_meta');
    const signed=await p.a.invocation.prepare(caller,h.sessionRef,'metadata',{});
    assert.throws(()=>attachOanMetadata({_meta:{[runtimeMetadataKey()]:{}}},'_meta',signed),/reserved_identity_metadata/);
    assert.throws(()=>detachOanMetadata({_meta:[] as any},'_meta'),/protection_required|invalid_protocol_metadata/);
    await p.b.invocation.receive(caller,signed,{},async()=>({ok:true}));
    await assert.rejects(p.b.invocation.inspect({...caller,tenantId:'other'},'metadata'),/invocation_access_denied/);
    await assert.rejects(p.b.invocation.receive({...caller,tenantId:'other'},signed,{},async()=>({})),/policy_denied|session_access_denied/);
    void a;
  }finally{p.close();}
});
test('G3 tools: only installed workflow is advertised and reserved key/caller injection is rejected',async()=>{
  const p=await pair();try{
    const host=new RuntimeToolHost({caller,directory:new ResourceDirectory(),verification:p.a.workflow});
    assert(host.list().some(t=>t.name==='identity.verification.begin'));
    const result=await host.call('identity.verification.begin',{input:p.a.input}) as any;
    assert.equal((await host.call('session.inspect',{sessionRef:result.sessionRef}) as any).state,'pending');
    await assert.rejects(host.call('session.begin',{input:{...p.a.input,callerId:'spoof'}}),/host_only_argument/);
    const native={name:'echo',arguments:{text:'a'},_meta:{native:'kept'}};
    assert.deepEqual(detachOanMetadata(attachOanMetadata(native,'_meta',{} as any),'_meta').object,native);
    await assert.rejects(p.a.workflow.advance(caller,result.sessionRef,{profile:'oan-session-v1',kind:'client-hello',body:null,jws:'x'}),/invalid_handshake_message/);
  }finally{p.close();}
});

function runtimeMetadataKey(){return 'openagenet.xyz/oan-message-v1';}
