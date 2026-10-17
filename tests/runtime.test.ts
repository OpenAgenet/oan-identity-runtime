// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createOanIdentityRecord } from '@openagenet/oan-sdk-ts';
import { IdentityCatalog, KeyProviderRegistry, MemoryKeyProvider, MemoryAuditSink, PolicyEngine, IdentityRuntime, ReplayCache, verifyPinnedMessage, sealBlob, openBlob, digestJson, type SignIntent, type SessionRecord } from '../src/index.js';
import { SqliteBlobStore } from '../src/store/sqlite.js';

test('resource signs its own payload with exact policy and session binding', async () => {
  const identity = await createOanIdentityRecord({ label: 'local-test', resourceType: 'skill', kind: 'agent' });
  const peer = 'did:oan:K7mQ9:22222222222222222222222222222222';
  const catalog = new IdentityCatalog();
  await catalog.add({ id: 'resource', did: identity.did, kind: 'resource', status: 'registered', verificationMethodId: identity.verificationMethodId, keyRef: 'key', didDocument: identity.didDocument, evidenceRefs: [] });
  const keys = new MemoryKeyProvider();
  await keys.importJwk('key', identity.verificationMethodId, identity.privateKeyJwk);
  const audit = new MemoryAuditSink();
  const session: SessionRecord = { id: 'session', localDid: identity.did, peerDid: peer, state: 'authenticated', expiresAt: new Date(Date.now() + 60000).toISOString() };
  const policy = new PolicyEngine([{ callerId: 'test-host', identityRef: 'resource', audienceDid: peer, purpose: 'request', protocol: 'http', operation: 'tools/call' }]);
  const runtime = new IdentityRuntime({ catalog, keys: new KeyProviderRegistry([keys], [{ id: 'key', providerId: 'memory', providerKeyId: 'key', purposes: ['request'] }]), audit, policy, sessions: { async requireAuthenticated() { return session; } } });
  const intent: SignIntent = { identityRef: 'resource', audienceDid: peer, purpose: 'request', protocol: 'http', protocolVersion: 'test-http-v1', operation: 'tools/call', serviceRef: peer + '#service', sessionId: 'session', requestId: 'req', payload: { tool: 'echo', text: 'hello' } };
  const signed = await runtime.signIntent({ callerId: 'test-host' }, intent);
  const pinned = { senderDid: identity.did, audienceDid: peer, publicKeyJwk: identity.publicKeyJwk, verificationMethod: identity.verificationMethodId, protocolVersion: 'test-http-v1', operation: 'tools/call', serviceRef: peer + '#service', sessionId: 'session', requestId: 'req', purpose: 'request' as const, protocol: 'http' as const, replay: new ReplayCache() };
  await assert.rejects(verifyPinnedMessage(signed, { ...pinned, operation: 'tools/delete' }), /message_binding_mismatch/);
  assert.deepEqual(await verifyPinnedMessage(signed, pinned), { signatureValid: true, registrationTrust: 'not_checked' });
  await assert.rejects(verifyPinnedMessage(signed, pinned), /replay_detected/);
  const modified = structuredClone(signed); modified.payload = { tool: 'delete' };
  await assert.rejects(verifyPinnedMessage(modified, { ...pinned, replay: new ReplayCache() }), /payload_digest_mismatch/);
  await assert.rejects(verifyPinnedMessage(signed, { ...pinned, audienceDid: identity.did }), /message_binding_mismatch/);
  await assert.rejects(runtime.signIntent({ callerId: 'attacker' }, intent), /policy_denied/);
  session.state = 'challenged';
  await assert.rejects(runtime.signIntent({ callerId: 'test-host' }, intent), /session_not_authenticated/);
  const exposed = await catalog.get('resource'); exposed.status = 'disabled';
  assert.equal((await catalog.get('resource')).status, 'registered');
  assert.equal(JSON.stringify(await runtime.listIdentities({ callerId: 'test-host' })).includes('privateKeyJwk'), false);
  assert.equal(JSON.stringify(await runtime.listIdentities({ callerId: 'test-host' })).includes('keyRef'), false);
  assert.deepEqual(await runtime.listIdentities({ callerId: 'attacker' }), []);
  assert.equal(JSON.stringify(audit.list()).includes('hello'), false);
});

test('encryption binds ID and generation; CAS protects concurrent writes', async () => {
  const store = new SqliteBlobStore(':memory:');
  try {
    const key = randomBytes(32);
    const blob = sealBlob('secret', key, 'identity', 1);
    assert.equal(await store.compareAndSwap('identity', 0, blob), 1);
    const stored = (await store.load('identity'))!;
    assert.equal(openBlob(stored.ciphertext, key, 'identity', stored.generation), 'secret');
    assert.throws(() => openBlob(blob, key, 'other', 1), /authentication_failed/);
    assert.throws(() => openBlob(blob, key, 'identity', 2), /authentication_failed/);
    assert.throws(() => openBlob(blob, randomBytes(32), 'identity', 1), /authentication_failed/);
    await assert.rejects(store.compareAndSwap('identity', 0, blob), /generation_conflict/);
    await assert.rejects(store.compareAndSwap('identity', 9, blob), /generation_conflict/);
    assert.equal(await store.compareAndSwap('identity', 1, sealBlob('updated', key, 'identity', 2)), 2);
  } finally { store.close(); }
});
test('replay capacity fails closed and scoped keys do not collide', async () => {
  const replay = new ReplayCache(2);
  await replay.consume('a', 'nonce', 100, 1);
  await replay.consume('b', 'nonce', 100, 1);
  await assert.rejects(replay.consume('c', 'nonce', 100, 1), /cache_full/);
  await assert.rejects(replay.consume('a', 'nonce', 100, 1), /replay_detected/);
  await replay.consume('c', 'nonce', 200, 101);
});

test('rejects lossy non-JSON signing payloads', async () => {
  for (const value of [NaN, Infinity, undefined, { missing: undefined }, [undefined], new Date(), [, 1]]) {
    await assert.rejects(digestJson(value), /invalid_json_payload/);
  }
  assert.equal(await digestJson({ b: 2, a: 1 }), await digestJson({ a: 1, b: 2 }));
});

test('LOC-01/EVD-03: caller cannot select another identity; controller signer cannot impersonate resource; approval mutation is isolated',async()=>{
  const controller=await createOanIdentityRecord({label:'controller',kind:'subject',resourceType:'controller'});
  const resource=await createOanIdentityRecord({label:'resource',kind:'agent',resourceType:'skill',ownerSubjectDid:controller.did});
  const peer='did:oan:K7mQ9:'+'2'.repeat(32),catalog=new IdentityCatalog(),keys=new MemoryKeyProvider();
  await catalog.add({id:'resource',did:resource.did,kind:'resource',status:'registered',verificationMethodId:resource.verificationMethodId,keyRef:'key',didDocument:resource.didDocument,evidenceRefs:[]});
  await keys.importJwk('controller-key',controller.verificationMethodId,controller.privateKeyJwk);
  await keys.importJwk('resource-key',resource.verificationMethodId,resource.privateKeyJwk);
  let wrongKey=true;
  const registry=new KeyProviderRegistry([keys]);
  const audit=new MemoryAuditSink();
  const intent:SignIntent={identityRef:'resource',audienceDid:peer,purpose:'request',protocol:'http',protocolVersion:'test-http-v1',operation:'echo',serviceRef:peer+'#service',sessionId:'session',requestId:'req',payload:{text:'approved'}};
  const allowed=new PolicyEngine([{callerId:'owner',identityRef:'resource',audienceDid:peer,purpose:'request',protocol:'http',operation:'echo'}]);
  const runtime=new IdentityRuntime({catalog,keys:{resolve:()=>registry.signerFor({id:'key',providerId:'memory',providerKeyId:wrongKey?'controller-key':'resource-key',purposes:['request']},'request')},audit,
    sessions:{async requireAuthenticated(){return {id:'session',localDid:resource.did,peerDid:peer,state:'authenticated',expiresAt:new Date(Date.now()+60000).toISOString()};}},
    policy:{canAccessIdentity:(c,r)=>allowed.canAccessIdentity(c,r),async authorize(c,i){await allowed.authorize(c,i);(intent.payload as any).text='changed-after-approval';}}});
  await assert.rejects(runtime.signIntent({callerId:'attacker'},intent),/policy_denied/);
  await assert.rejects(runtime.signIntent({callerId:'owner'},{...intent,identityRef:'controller'}),/policy_denied/);
  await assert.rejects(runtime.signIntent({callerId:'owner'},intent),/identity_key_binding_mismatch/);
  wrongKey=false;(intent.payload as any).text='approved';
  const signed=await runtime.signIntent({callerId:'owner'},intent);
  assert.equal(signed.context.senderDid,resource.did);assert.deepEqual(signed.payload,{text:'approved'});
  assert.equal(JSON.stringify(audit.list()).includes('approved'),false);
});
