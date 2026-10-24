// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalJson, createOanIdentityRecord, createJwkOanSigner } from '@openagenet/oan-sdk-ts';
import { createNativeProofHttpFetch, createActorNativeHttpFetch } from '../src/invocation/native-proof-http.js';

const digest = (body: string) => `sha256:${createHash('sha256').update(body).digest('hex')}`;
async function fixture() {
  const identity = await createOanIdentityRecord({ label: 'independent-peer', resourceType: 'skill', kind: 'agent' });
  const signer = await createJwkOanSigner(identity.verificationMethodId, identity.privateKeyJwk as JsonWebKey);
  const localDid = 'did:oan:local-client';
  const resolvePeer = async (did: string) => ({ did, verificationMethod: signer.keyId, publicKeyJwk: identity.publicKeyJwk as JsonWebKey, validUntil: Date.now() + 120000 });
  const proof = async (requestId: string, requestBody: string, responseBody: string, kind = 'sidecar-response') => {
    const envelope = { kind, senderDid: identity.did, audienceDid: localDid, targetResourceDid: identity.did,
      requestId, requestPayloadDigest: digest(requestBody), payloadDigest: digest(responseBody), status: 200 };
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: signer.keyId, typ: 'oan-native-response+jws' })).toString('base64url');
    const payload = Buffer.from(canonicalJson(envelope)).toString('base64url');
    const value = `${header}.${payload}.${Buffer.from(await signer.signPreparedInput(new TextEncoder().encode(`${header}.${payload}`))).toString('base64url')}`;
    return Buffer.from(JSON.stringify({ envelope, signature: { verificationMethod: signer.keyId, value } })).toString('base64url');
  };
  const options = { endpoint: 'http://localhost:47891/native', methods: ['POST'], localDid, peerDid: identity.did,
    responseProofKind: 'sidecar-response' as const, resolvePeer,
    sign: async (input: { requestId: string; rawBodyDigest: string; body: Uint8Array }) => {
      assert.equal(input.rawBodyDigest, digest(Buffer.from(input.body).toString()));
      return { 'x-oan-request-id': input.requestId };
    } };
  return { options, proof };
}

test('native proof client uses explicit peers and independent concurrent correlation without demo metadata', async () => {
  const { options, proof } = await fixture(); const receipts: unknown[] = [];
  const call = createNativeProofHttpFetch({ ...options, onVerified: item => { receipts.push(item); },
    transport: async (_url, init) => {
      const body = String(init!.body); const id = new Headers(init!.headers).get('x-oan-request-id')!;
      await new Promise(resolve => setTimeout(resolve, body === 'first' ? 15 : 1));
      return new Response(body, { headers: { 'x-oan-response-envelope': await proof(id, body, body) } });
    } });
  assert.deepEqual(await Promise.all(['first', 'second'].map(async body => (await call(options.endpoint, { method: 'POST', body })).text())), ['first', 'second']);
  assert.equal(receipts.length, 2);
});

test('native proof client rejects missing, swapped, altered and wrong-kind responses before trusted output', async () => {
  const { options, proof } = await fixture();
  for (const mode of ['missing', 'request', 'body', 'kind']) {
    let verified = false;
    const call = createNativeProofHttpFetch({ ...options, onVerified: () => { verified = true; },
      transport: async (_url, init) => new Response(mode === 'body' ? 'tampered' : 'result', { headers: mode === 'missing' ? {} : {
        'x-oan-response-envelope': await proof(mode === 'request' ? 'other-request' : new Headers(init!.headers).get('x-oan-request-id')!, 'input', 'result', mode === 'kind' ? 'gateway-response' : 'sidecar-response') } }) });
    await assert.rejects(call(options.endpoint, { method: 'POST', body: 'input' }), /response_proof/);
    assert.equal(verified, false);
  }
});

test('native proof client verifies terminal SSE then removes proof for the original SDK', async () => {
  const { options, proof } = await fixture(); const body = 'event: message\ndata: {}\n\n';
  const call = createNativeProofHttpFetch({ ...options,
    transport: async (_url, init) => new Response(body + '\nevent: oan-response-proof\ndata: ' + await proof(new Headers(init!.headers).get('x-oan-request-id')!, 'input', body) + '\n\n', { headers: { 'content-type': 'Text/Event-Stream; charset=utf-8' } }) });
  assert.equal(await (await call(options.endpoint, { method: 'POST', body: 'input' })).text(), body);
  assert.throws(() => createNativeProofHttpFetch({ ...options, responseProofKind: undefined as any }), /invalid_native_proof_config/);
});

test('actor client composes headers with explicit session, tenant and native operation mapping', async () => {
  const { options, proof } = await fixture(); let signed = 0;
  const session = { scope: { initiatorDid: options.localDid, responderDid: options.peerDid, serviceRef: 'service', protocol: 'mcp', protocolVersion: '2025-11-25' }, transcript: [{ body: { sessionId: 'session' } }] } as any;
  const actor = { did: options.localDid, tenantId: 'user-workspace', resolvePeer: options.resolvePeer,
    signRequest: async (received: any, id: string, bodyDigest: string, operation: string, binding: any) => {
      signed++; assert.equal(received.scope.responderDid, options.peerDid); assert.equal(bodyDigest, digest('input'));
      assert.equal(operation, 'tools/call'); assert.deepEqual(binding, { method: 'POST', target: '/native', mcpSessionId: 'native-session' });
      return { context: { requestId: id } } as any;
    } };
  const call = createActorNativeHttpFetch({ ...options, actor, session,
    operation: request => { assert.equal(Buffer.from(request.body).toString(), 'input'); return 'tools/call'; },
    transport: async (_url, init) => {
      const headers = new Headers(init!.headers), envelope = JSON.parse(Buffer.from(headers.get('x-oan-envelope')!, 'base64url').toString());
      assert.equal(envelope.tenantId, 'user-workspace'); assert.equal(envelope.targetResourceDid, options.peerDid);
      assert.equal(envelope.sessionId, 'session');
      return new Response('result', { headers: { 'x-oan-response-envelope': await proof(headers.get('x-oan-request-id')!, 'input', 'result') } });
    } });
  session.scope.responderDid = 'mutated';
  assert.equal(await (await call(options.endpoint, { method: 'POST', body: 'input', headers: { 'mcp-session-id': 'native-session' } })).text(), 'result');
  assert.equal(signed, 1);
  session.scope.initiatorDid = 'another-caller';
  assert.throws(() => createActorNativeHttpFetch({ ...options, actor, session, operation: 'tools/call' }), /invalid_native_proof_config/);
});
