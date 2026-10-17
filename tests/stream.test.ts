// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { EncryptedKeyProvider, SqliteBlobStore, DurableStreamVerifier, STREAM_GENESIS_DIGEST, digestJson } from '../src/index.js';
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
