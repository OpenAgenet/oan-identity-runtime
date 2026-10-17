// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import test from 'node:test';
import assert from 'node:assert/strict';
import { loadLab, host, ReplayCache, verifyPinnedMessage } from './fixtures.mjs';
import { digestJson, ResourceDirectory, FRAMEWORK_CAPABILITIES } from '../../dist/index.js';

const pairs = [['a2a-a','a2a-b','a2a'],['a2a-b','a2a-a','a2a'],['a2a-a','mcp','mcp'],['hermes-a','hermes-b','a2a'],['hermes-b','hermes-a','a2a']];
for (const [localName,peerName,protocol] of pairs) test(`RT-01/02 ${localName} -> ${peerName}: registered resource key signs; peer verifies`, async () => {
  const {actors}=await loadLab(), local=actors[localName],peer=actors[peerName];
  const h=await host(local,peer,protocol);
  const message=await h.runtime.signIntent(h.caller,h.intent);
  assert.equal(message.context.senderDid,local.did);
  assert.notEqual(message.context.senderDid,local.controllerDid);
  assert.deepEqual(await verifyPinnedMessage(message,h.pinned),{signatureValid:true,registrationTrust:'not_checked'});
  await assert.rejects(verifyPinnedMessage(message,h.pinned),/replay_detected/);
  for (const [field,value] of [['audienceDid',local.did],['senderDid',local.controllerDid],['requestId','other'],['sessionId','other'],['protocol',protocol==='mcp'?'a2a':'mcp']]) {
    await assert.rejects(verifyPinnedMessage(message,{...h.pinned,[field]:value,replay:new ReplayCache()}),/message_binding_mismatch/);
  }
  const changed=structuredClone(message);changed.payload={value:'tampered'};
  await assert.rejects(verifyPinnedMessage(changed,{...h.pinned,replay:new ReplayCache()}),/payload_digest_mismatch/);
  await assert.rejects(verifyPinnedMessage(message,{...h.pinned,now:Date.parse(message.context.expiresAt)+1,replay:new ReplayCache()}),/message_time_invalid/);
  await assert.rejects(verifyPinnedMessage(message,{...h.pinned,publicKeyJwk:actors['controller-a'].identity.publicKeyJwk,replay:new ReplayCache()}),/message_signature_invalid/);
  await assert.rejects(h.runtime.signIntent({...h.caller,tenantId:'other'},h.intent),/policy_denied/);
  await assert.rejects(h.runtime.signIntent(h.caller,{...h.intent,operation:'delete'}),/policy_denied/);
  const exported=JSON.stringify(await h.runtime.listIdentities(h.caller));
  assert.ok(!exported.includes('privateKeyJwk') && !exported.includes('keyRef'));
  h.session.state='challenged';
  await assert.rejects(h.runtime.signIntent(h.caller,h.intent),/session_not_authenticated/);
});

test('RT-03 reverse resource response is bound to the signed request digest',async()=>{
  const {actors}=await loadLab(); const a=await host(actors['a2a-a'],actors.mcp,'mcp');
  const b=await host(actors.mcp,actors['a2a-a'],'mcp');
  const request=await a.runtime.signIntent(a.caller,a.intent);
  const requestDigest=await digestJson(request);
  const responseIntent={...b.intent,purpose:'response',serviceRef:a.intent.serviceRef,requestDigest,payload:{result:'recorded'}};
  const response=await b.runtime.signIntent(b.caller,responseIntent);
  const pinned={...b.pinned,purpose:'response',serviceRef:a.intent.serviceRef,requestDigest};
  await verifyPinnedMessage(response,pinned);
  await assert.rejects(verifyPinnedMessage(response,{...pinned,requestDigest:'sha256:'+'0'.repeat(64),replay:new ReplayCache()}),/message_binding_mismatch/);
  await assert.rejects(b.runtime.signIntent(b.caller,{...responseIntent,requestDigest:undefined}),/message_correlation_required/);
});

test('RT-04 reloading fixed fixtures preserves DID, key and signing identity',async()=>{
  const first=await loadLab(),second=await loadLab();
  for(const name of Object.keys(first.actors)) {
    assert.equal(first.actors[name].did,second.actors[name].did);
    assert.deepEqual(first.actors[name].identity.privateKeyJwk,second.actors[name].identity.privateKeyJwk);
  }
});

test('RT-05 optional official Discovery read-only check for all five resource bindings',{skip:process.env.OAN_LAB_LIVE!=='1'?'Set OAN_LAB_LIVE=1 for explicit public read-only requests':false},async()=>{
  const {manifest,actors}=await loadLab();
  const directory=new ResourceDirectory({discoveryEndpoint:manifest.baseUrl,fetchImpl:(url,init)=>fetch(url,{...init,signal:AbortSignal.timeout(15000)})});
  for(const name of Object.keys(manifest.resources)) {
    const actor=actors[name];const result=await directory.resolve(actor.did);
    assert.equal(result.package.didDocument.id,actor.did);
    assert.equal(await digestJson(result.package.didDocument),await digestJson(actor.document));
    assert.ok(result.package.didDocument.service.some(s=>s.serviceEndpoint===actor.registeredAccess.url));
  }
});

test('RT-06 capabilities do not claim real mutual authentication or protected invocation',()=>{
  assert.equal(FRAMEWORK_CAPABILITIES.mutualAuthentication,false);
  assert.equal(FRAMEWORK_CAPABILITIES.protectedInvocation,false);
});
test('RT-07 real four-message mutual verification via Hermes/Skill',{skip:'BLOCKED: IdentityVerificationWorkflow/SessionHandshake implementation and trusted evidence verifier required'},()=>{});
test('RT-08 persistent replay rejection after Runtime restart',{skip:'BLOCKED: durable ReplayStore host implementation required; fixture reload is not replay persistence'},()=>{});
