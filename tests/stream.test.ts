// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createOanIdentityRecord, signDidDocumentProof } from '@openagenet/oan-sdk-ts';
import { EncryptedKeyProvider, SqliteBlobStore, DurableStreamVerifier, STREAM_GENESIS_DIGEST, digestJson,
  IdentityCatalog, IdentityRuntime, MemoryAuditSink, PolicyEngine, SqliteReplayStore, StreamingInvocation } from '../src/index.js';
const caller = { callerId: 'stream-owner', tenantId: 'stream-tenant' };
const hash = (n: string) => `sha256:${n.repeat(64 / n.length)}`;
function event(sequence: number, previousDigest: string, state: 'partial'|'complete'|'cancelled' = 'partial') {
  return { streamId: 'task-1', taskId: 'task-a', sessionId: 'session-a', requestId: 'request-a',
    peerDid: 'did:oan:peer', audienceDid: 'did:oan:local', requestDigest: hash('a'), sequence,
    previousDigest, messageDigest: hash(sequence.toString(16)), nonce: `nonce-${sequence}`, state };
}
async function fixture() {
  const store = new SqliteBlobStore(':memory:'), keys = new EncryptedKeyProvider(store);
  keys.unlock(randomBytes(32));
  return { verifier: new DurableStreamVerifier(keys), close: () => { keys.lock(); store.close(); } };
}
test('G5 stream accepts ordered partial events and one terminal event, then survives inspection', async () => {
  const f = await fixture();
  try {
    const first = event(0, STREAM_GENESIS_DIGEST);
    await f.verifier.accept(caller, first);
    const second = event(1, first.messageDigest);
    await f.verifier.accept(caller, second);
    const done = event(2, second.messageDigest, 'complete');
    assert.deepEqual(await f.verifier.accept(caller, done), { sequence: 2, state: 'complete', terminal: true });
    assert.equal(await f.verifier.inspect(caller, 'task-1'), 'complete');
    await assert.rejects(f.verifier.accept(caller, event(3, done.messageDigest)), /stream_terminal/);
  } finally { f.close(); }
});
test('G5 stream rejects gaps, reordering, wrong binding and duplicate events without advancing state', async () => {
  const f = await fixture();
  try {
    const first = event(0, STREAM_GENESIS_DIGEST); await f.verifier.accept(caller, first);
    await assert.rejects(f.verifier.accept(caller, event(2, first.messageDigest)), /stream_sequence_gap/);
    await assert.rejects(f.verifier.accept(caller, event(0, STREAM_GENESIS_DIGEST)), /stream_duplicate_or_reordered/);
    await assert.rejects(f.verifier.accept(caller, { ...event(1, hash('b')), taskId: 'other' }), /stream_binding_mismatch/);
    assert.equal(await f.verifier.inspect(caller, 'task-1'), 'partial');
  } finally { f.close(); }
});
test('G5 stream binds artifact bytes and caller/tenant, and does not retain artifact contents', async () => {
  const f = await fixture();
  try {
    const artifact = { bytes: 'stable' }, artifactDigest = await digestJson(artifact);
    const first = { ...event(0, STREAM_GENESIS_DIGEST), artifact, artifactDigest };
    await f.verifier.accept(caller, first);
    await assert.rejects(f.verifier.accept(caller, { ...event(1, first.messageDigest), artifact, artifactDigest: hash('f') }), /artifact_digest_mismatch/);
    await assert.rejects(f.verifier.inspect({ callerId: caller.callerId, tenantId: 'other' }, 'task-1'), /stream_access_denied/);
  } finally { f.close(); }
});
test('G5 stream state is recovered by a new verifier over the same encrypted store', async () => {
  const store = new SqliteBlobStore(':memory:'), keys = new EncryptedKeyProvider(store); keys.unlock(randomBytes(32));
  try {
    const first = event(0, STREAM_GENESIS_DIGEST);
    await new DurableStreamVerifier(keys).accept(caller, first);
    const restarted = new DurableStreamVerifier(keys);
    await restarted.accept(caller, event(1, first.messageDigest, 'cancelled'));
    assert.equal(await restarted.inspect(caller, 'task-1'), 'cancelled');
  } finally { keys.lock(); store.close(); }
});
test('G5 concurrent stream events use CAS and only one next sequence commits', async () => {
  const f = await fixture();
  try {
    const first = event(0, STREAM_GENESIS_DIGEST); await f.verifier.accept(caller, first);
    const results = await Promise.allSettled([
      f.verifier.accept(caller, event(1, first.messageDigest)),
      f.verifier.accept(caller, event(1, first.messageDigest)),
    ]);
    assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
    assert.equal(await f.verifier.inspect(caller, 'task-1'), 'partial');
  } finally { f.close(); }
});

test('G5 sequence rejection does not consume the event nonce before the missing predecessor arrives', async () => {
  const f = await fixture();
  try {
    const first = event(0, STREAM_GENESIS_DIGEST); await f.verifier.accept(caller, first);
    const gap = event(2, hash('1'));
    await assert.rejects(f.verifier.accept(caller, gap), /stream_sequence_gap/);
    await f.verifier.accept(caller, event(1, first.messageDigest));
    await f.verifier.accept(caller, gap);
    assert.equal(await f.verifier.inspect(caller, 'task-1'), 'partial');
  } finally { f.close(); }
});

test('G5 stream state survives a file-store close and process-style reopen', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'oan-g5-restart-'));
  const database = join(directory, 'runtime.sqlite'), master = randomBytes(32);
  try {
    const firstStore = new SqliteBlobStore(database), firstKeys = new EncryptedKeyProvider(firstStore); firstKeys.unlock(master);
    const first = event(0, STREAM_GENESIS_DIGEST);
    await new DurableStreamVerifier(firstKeys).accept(caller, first);
    firstKeys.lock(); firstStore.close();
    const reopenedStore = new SqliteBlobStore(database), reopenedKeys = new EncryptedKeyProvider(reopenedStore); reopenedKeys.unlock(master);
    const reopened = new DurableStreamVerifier(reopenedKeys);
    await reopened.accept(caller, event(1, first.messageDigest, 'cancelled'));
    assert.equal(await reopened.inspect(caller, 'task-1'), 'cancelled');
    reopenedKeys.lock(); reopenedStore.close();
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('G5 streaming boundary rejects event metadata substituted around a valid signed message', async () => {
  const f = await fixture();
  try {
    const first = event(0, STREAM_GENESIS_DIGEST);
    await f.verifier.accept(caller, first);
    await assert.rejects(f.verifier.accept(caller, { ...first, sessionId: 'other-session' }), /stream_binding_mismatch|stream_sequence_gap|stream_duplicate_or_reordered/);
  } finally { f.close(); }
});

async function streamingPair() {
  const identities = await Promise.all(['stream-a', 'stream-b'].map(async label => {
    const identity = await createOanIdentityRecord({ label, kind: 'agent', resourceType: 'agent_service' });
    identity.didDocument = await signDidDocumentProof(identity.didDocument, identity);
    return identity;
  }));
  const caller = { callerId: 'stream-wrapper-owner', tenantId: 'stream-wrapper-tenant' };
  const sides = await Promise.all(identities.map(async (identity, index) => {
    const peer = identities[1 - index];
    const store = new SqliteBlobStore(':memory:');
    const keys = new EncryptedKeyProvider(store); keys.unlock(randomBytes(32));
    await keys.importJwk('stream-key', identity.verificationMethodId, identity.privateKeyJwk as JsonWebKey);
    const catalog = new IdentityCatalog();
    await catalog.add({ id: 'resource', did: identity.did, kind: 'resource', status: 'registered',
      verificationMethodId: identity.verificationMethodId, keyRef: 'stream-key', didDocument: identity.didDocument, evidenceRefs: ['fixture'] });
    const policy = new PolicyEngine([{ callerId: caller.callerId, tenantId: caller.tenantId, identityRef: 'resource',
      audienceDid: peer.did, purpose: 'event', protocol: 'a2a', operation: 'tasks/send:stream' }]);
    const sessions = { async requireAuthenticated() { return { id: 'session-stream', localDid: identity.did, peerDid: peer.did,
      state: 'authenticated' as const, expiresAt: new Date(Date.now() + 60_000).toISOString(),
      binding: { serviceRef: 'did:oan:stream-service#a2a', protocol: 'a2a', protocolVersion: '1.0' } }; },
      async requireAuthenticatedForCaller() { return this.requireAuthenticated(); } };
    const runtime = new IdentityRuntime({ catalog, keys: { resolve: () => keys.getSigner('stream-key') },
      audit: new MemoryAuditSink(), sessions, policy });
    const replay = new SqliteReplayStore(':memory:');
    const resolvePeer = async (did: string) => {
      const found = identities.find(item => item.did === did);
      if (!found) throw new Error('unknown_peer');
      return { did, verificationMethod: found.verificationMethodId, publicKeyJwk: found.publicKeyJwk as JsonWebKey, validUntil: Date.now() + 120_000 };
    };
    const streams = new DurableStreamVerifier(keys);
    const invocation = new StreamingInvocation({ identityRef: 'resource', localDid: identity.did, peerDid: peer.did, runtime,
      sessions, replay, resolvePeer, journal: keys, streams,
      profile: { protocol: 'a2a', protocolVersion: '1.0', serviceRef: 'did:oan:stream-service#a2a', operation: 'tasks/send:stream' },
      async authorize() {} });
    return { identity, peer, invocation, streams, replay, keys, store, caller };
  }));
  return { a: sides[0], b: sides[1], close() { for (const side of sides) { side.replay.close(); side.keys.lock(); side.store.close(); } } };
}

test('G5 signed A2A stream wrapper binds event metadata, artifact digest and callback DID before durable commit', async () => {
  const pair = await streamingPair();
  try {
    const base = { streamId: 'signed-stream', taskId: 'task-signed', sessionId: 'session-stream', requestId: 'request-signed',
      peerDid: pair.b.identity.did, audienceDid: pair.a.identity.did, requestDigest: hash('a'), sequence: 0,
      previousDigest: STREAM_GENESIS_DIGEST, messageDigest: hash('0'), nonce: 'placeholder', state: 'partial' as const,
      callbackDid: pair.b.identity.did, artifact: { value: 'artifact' } };
    const artifactDigest = await digestJson(base.artifact);
    const prepared = await pair.b.invocation.prepareEvent(pair.b.caller, 'session-stream', { ...base, artifactDigest }, { delta: 1 });
    const accepted = await pair.a.invocation.receiveEvent(pair.a.caller, prepared.message, prepared.event, { delta: 1 });
    assert.deepEqual(accepted, { accepted: true, terminal: false });
    await assert.rejects(pair.a.invocation.receiveEvent(pair.a.caller, prepared.message,
      { ...prepared.event, callbackDid: pair.a.identity.did }, { delta: 1 }), /stream_binding_mismatch/);
    await assert.rejects(pair.a.invocation.receiveEvent(pair.a.caller, prepared.message,
      { ...prepared.event, artifactDigest: hash('f') }, { delta: 1 }), /stream_binding_mismatch/);
    assert.equal(await pair.a.streams.inspect(pair.a.caller, 'signed-stream'), 'partial');
  } finally { pair.close(); }
});

test('G5 signed A2A stream wrapper rejects tampered payload, sequence and nonce without advancing state', async () => {
  const pair = await streamingPair();
  try {
    const input = { streamId: 'signed-stream-2', taskId: 'task-signed-2', sessionId: 'session-stream', requestId: 'request-signed-2',
      peerDid: pair.b.identity.did, audienceDid: pair.a.identity.did, requestDigest: hash('a'), sequence: 0,
      previousDigest: STREAM_GENESIS_DIGEST, messageDigest: hash('0'), nonce: 'placeholder', state: 'partial' as const };
    const prepared = await pair.b.invocation.prepareEvent(pair.b.caller, 'session-stream', input, { delta: 2 });
    await assert.rejects(pair.a.invocation.receiveEvent(pair.a.caller, prepared.message, prepared.event, { delta: 999 }), /payload_digest_mismatch|stream_message_digest_mismatch|stream_binding_mismatch/);
    await assert.rejects(pair.a.invocation.receiveEvent(pair.a.caller, prepared.message,
      { ...prepared.event, sequence: 1 }, { delta: 2 }), /stream_binding_mismatch|stream_message_digest_mismatch/);
    await assert.rejects(pair.a.invocation.receiveEvent(pair.a.caller, prepared.message,
      { ...prepared.event, nonce: 'forged-nonce' }, { delta: 2 }), /stream_binding_mismatch/);
    assert.equal(await pair.a.streams.inspect(pair.a.caller, 'signed-stream-2'), 'not_found');
  } finally { pair.close(); }
});
