// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import test from 'node:test';
import assert from 'node:assert/strict';
import { createOanIdentityRecord } from '@openagenet/oan-sdk-ts';
import { compactVerify, importJWK } from 'jose';
import { IdentityCatalog, IdentityRuntime, PolicyEngine, MemoryAuditSink, MemoryKeyProvider, KeyProviderRegistry, observePublication, type SignIntent } from '../src/index.js';
import { SqliteBlobStore } from '../src/store/sqlite.js';

async function setup() {
  const identity = await createOanIdentityRecord({ label: 'assistant', resourceType: 'controller', kind: 'subject' });
  const catalog = new IdentityCatalog();
  await catalog.add({ id: 'assistant', did: identity.did, kind: 'controller', status: 'registered', keyRef: 'assistant-key', verificationMethodId: identity.verificationMethodId, didDocument: identity.didDocument, evidenceRefs: [] });
  const keys = new MemoryKeyProvider();
  await keys.importJwk('assistant-key', identity.verificationMethodId, identity.privateKeyJwk);
  const peer = 'did:oan:K7mQ9:22222222222222222222222222222222';
  const rules = ['request', 'response', 'challenge', 'event'].map(purpose => ({ callerId: 'host', tenantId: 'tenant-a', identityRef: 'assistant', audienceDid: peer, purpose: purpose as SignIntent['purpose'], protocol: 'http' as const, operation: 'echo' }));
  const runtime = new IdentityRuntime({ catalog, keys: new KeyProviderRegistry([keys], [{ id: 'assistant-key', providerId: 'memory', providerKeyId: 'assistant-key', purposes: ['request', 'response', 'event'] }]), policy: new PolicyEngine(rules), audit: new MemoryAuditSink(), sessions: { async requireAuthenticated(id) { return { id, localDid: identity.did, peerDid: peer, expiresAt: new Date(Date.now()+60000).toISOString(), state: 'authenticated' }; } } });
  const intent: SignIntent = { identityRef: 'assistant', audienceDid: peer, protocol: 'http', protocolVersion: 'http-test-v1', serviceRef: peer+'#service', purpose: 'request', operation: 'echo', sessionId: 'session', requestId: 'req', payload: { text: 'hello' } };
  return { identity, runtime, intent, keys, catalog };
}
test('assistant controller may communicate as itself with an independently verifiable JWS', async () => {
  const { identity, runtime, intent } = await setup();
  const signed = await runtime.signIntent({ callerId: 'host', tenantId: 'tenant-a' }, intent);
  const verified = await compactVerify(signed.signature.value, await importJWK(identity.publicKeyJwk, 'EdDSA'), { algorithms: ['EdDSA'] });
  assert.equal(verified.protectedHeader.kid, identity.verificationMethodId);
  assert.equal(JSON.parse(new TextDecoder().decode(verified.payload)).context.senderDid, identity.did);
  await assert.rejects(runtime.signIntent({ callerId: 'host', tenantId: 'tenant-b' }, intent), /policy_denied/);
});
test('handshake is separate and results/events require correlation', async () => {
  const { runtime, intent } = await setup(); const caller = { callerId: 'host', tenantId: 'tenant-a' };
  await assert.rejects(runtime.signIntent(caller, { ...intent, purpose: 'challenge' }), /unsupported:session_handshake/);
  await assert.rejects(runtime.signIntent(caller, { ...intent, purpose: 'response' }), /message_correlation_required/);
  const response = await runtime.signIntent(caller, { ...intent, purpose: 'response', requestDigest: 'sha256:'+'a'.repeat(64) });
  assert.equal(response.requestDigest, 'sha256:'+'a'.repeat(64));
  await assert.rejects(runtime.signIntent(caller, { ...intent, purpose: 'event' }), /stream_correlation_required/);
});
test('catalog rejects private document material and leaves no partial record', async () => {
  const { catalog, identity } = await setup();
  const document = structuredClone(identity.didDocument);
  document.verificationMethod![0].publicKeyJwk = identity.privateKeyJwk;
  await assert.rejects(catalog.add({ id: 'bad', did: identity.did, kind: 'resource', status: 'local_ready', keyRef: 'bad', verificationMethodId: identity.verificationMethodId, didDocument: document, evidenceRefs: [] }), /secret_in_public_material/);
  assert.equal((await catalog.list()).length, 1);
});
test('provider registry fails on unknown provider, duplicate provider and wrong purpose', async () => {
  const { keys } = await setup();
  const registry = new KeyProviderRegistry([keys]);
  const ref = { id: 'local', providerId: 'memory', providerKeyId: 'assistant-key', purposes: ['request'] };
  assert.equal((await registry.signerFor(ref, 'request')).algorithm, 'Ed25519');
  await assert.rejects(registry.signerFor(ref, 'capabilityInvocation'), /key_purpose_denied/);
  await assert.rejects(registry.signerFor({ ...ref, providerId: 'missing' }, 'request'), /provider_unavailable/);
  assert.throws(() => new KeyProviderRegistry([keys, keys]), /duplicate_key_provider/);
});
test('multi-record CAS is atomic and rolls back earlier writes', async () => {
  const store = new SqliteBlobStore(':memory:');
  try {
    await store.compareAndSwap('existing', 0, 'old');
    await assert.rejects(store.commit([{ id: 'candidate', expectedGeneration: 0, ciphertext: 'new' }, { id: 'existing', expectedGeneration: 9, ciphertext: 'wrong' }]), /generation_conflict/);
    assert.equal(await store.load('candidate'), undefined);
    assert.equal((await store.load('existing'))?.ciphertext, 'old');
    await store.commit([{ id: 'candidate', expectedGeneration: 0, ciphertext: 'new' }, { id: 'existing', expectedGeneration: 1, ciphertext: 'updated' }]);
    assert.equal((await store.load('existing'))?.generation, 2);
  } finally { store.close(); }
});
test('publication uncertainty cannot become rejection or confirmation without matching evidence', () => {
  const attempt = { attemptId: 'a', resourceDid: 'resource', candidateDigest: 'digest', idempotencyKey: 'stable', state: 'submitted' as const };
  const uncertain = observePublication(attempt, { kind: 'unknown' });
  assert.equal(uncertain.idempotencyKey, 'stable');
  assert.throws(() => observePublication(uncertain, { kind: 'rejected-before-acceptance' }), /reconciliation_required/);
  const evidence = { resourceDid: 'wrong', documentDigest: 'digest', packageVersion: '1', registrarVersion: '1', source: 'registrar', evidenceRef: 'verified' };
  assert.throws(() => observePublication(uncertain, { kind: 'confirmed', evidence }), /binding_mismatch/);
  assert.equal(observePublication(uncertain, { kind: 'confirmed', evidence: { ...evidence, resourceDid: 'resource' } }).state, 'registered');
});
