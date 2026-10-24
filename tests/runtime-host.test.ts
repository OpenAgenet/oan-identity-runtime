// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJson, createJwkOanSigner, createOanIdentityRecord } from '@openagenet/oan-sdk-ts';
import { RuntimeHostVerifier, splitNativeStreamProof, verifyNativeResponseProof } from '../src/host/runtime-host.js';
import { ReplayCache } from '../src/session/index.js';
import { MutualHandshake } from '../src/session/handshake.js';

test('native terminal stream proof requires one complete final event and preserves exact bytes', () => {
  const body = Buffer.from('event: message\ndata: {"id":1}\n\n');
  const marker = Buffer.from('\nevent: oan-response-proof\ndata: YWJj\n\n');
  const result = splitNativeStreamProof(Buffer.concat([body, marker]));
  assert.deepEqual(Buffer.from(result.body), body); assert.equal(result.encodedProof, 'YWJj');
  for (const invalid of [body, Buffer.concat([body, marker.subarray(0, -1)]), Buffer.concat([body, marker, marker]), Buffer.concat([body, marker, Buffer.from('extra')])]) assert.throws(() => splitNativeStreamProof(invalid), /stream_terminal_proof/);
});

test('formal Runtime host verifies a signed request against a bound session and replay store', async () => {
  const identity = await createOanIdentityRecord({ label: 'runtime-host', resourceType: 'skill', kind: 'agent' });
  const signer = await createJwkOanSigner(identity.verificationMethodId, identity.privateKeyJwk as JsonWebKey);
  const other = await createOanIdentityRecord({ label: 'runtime-peer', resourceType: 'skill', kind: 'agent' });
  const otherSigner = await createJwkOanSigner(other.verificationMethodId, other.privateKeyJwk as JsonWebKey);
  const peers = new Map([identity, other].map(item => [item.did, { did: item.did, verificationMethod: item.verificationMethodId, publicKeyJwk: item.publicKeyJwk as JsonWebKey, validUntil: Date.now() + 120000 }]));
  const peer = peers.get(other.did)!;
  const resolvePeer = async (did: string) => { const value = peers.get(did); if (!value) throw new Error('unknown_peer'); return value; };
  const host = new RuntimeHostVerifier(identity.did, signer, resolvePeer, new ReplayCache());
  const initiator = new MutualHandshake(other.did, otherSigner, resolvePeer);
  const responder = new MutualHandshake(identity.did, signer, resolvePeer);
  const scope = { initiatorDid: other.did, responderDid: identity.did, serviceRef: `${identity.did}#service-1`, protocol: 'mcp' as const, protocolVersion: '2025-11-25' };
  const hello = await initiator.begin(scope);
  const server = await responder.accept(scope, hello);
  const client = (await initiator.advance(hello.body.sessionId, server)).reply!;
  const confirmation = (await responder.advance(hello.body.sessionId, client)).reply!;
  await initiator.advance(hello.body.sessionId, confirmation);
  await host.addVerifiedSession({ scope, transcript: [hello, server, client, confirmation] });
  const validProof = { scope, transcript: [hello, server, client, confirmation] } as any;
  for (const dates of [{ createdAt: 'invalid', expiresAt: 'invalid' }, { createdAt: new Date(Date.now()+120000).toISOString(), expiresAt: new Date(Date.now()+150000).toISOString() }]) {
    const malformed = structuredClone(validProof);
    Object.assign(malformed.transcript[0].body, dates);
    await assert.rejects(host.addVerifiedSession(malformed), /session_transcript_unverified/);
  }
  const invalidEvidence = new RuntimeHostVerifier(identity.did, signer, async did => ({ ...await resolvePeer(did), validUntil: NaN }), new ReplayCache());
  await assert.rejects(invalidEvidence.addVerifiedSession(validProof), /session_transcript_unverified/);
  const opaqueContext = { workspace: 'independent-workspace' };
  const independent = new RuntimeHostVerifier(identity.did, signer, resolvePeer, new ReplayCache(),
    { tenantId: 'independent-tenant', requestContext: opaqueContext, requireHttpBinding: true });
  opaqueContext.workspace = 'mutated';
  assert.equal(independent.scope?.requestContext?.workspace, 'independent-workspace');
  assert.throws(() => new RuntimeHostVerifier(identity.did, signer, resolvePeer, new ReplayCache(),
    { tenantId: 'team', requestContext: { rawBodyDigest: 'override' } }), /invalid_host_request_context/);
  const rawBodyDigest = `sha256:${'a'.repeat(64)}`;
  const message = { context: { profile: 'oan-message-v1', senderDid: peer.did, audienceDid: identity.did, purpose: 'request', protocol: 'mcp', sessionId: hello.body.sessionId, messageId: 'm-1', requestId: 'request-1', nonce: 'nonce-1', createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 30000).toISOString(), payloadDigest: 'sha256:placeholder' }, operation: 'tools/call', serviceRef: scope.serviceRef, protocolVersion: '2025-11-25', payload: { rawBodyDigest }, signature: { verificationMethod: peer.verificationMethod, value: '' } } as any;
  const { digestJson } = await import('../src/verification/index.js');
  message.context.payloadDigest = await digestJson(message.payload);
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: peer.verificationMethod, typ: 'oan-message-v1+jws' })).toString('base64url');
  const payload = Buffer.from(canonicalJson({ context: message.context, operation: message.operation, serviceRef: message.serviceRef, protocolVersion: message.protocolVersion, payload: message.payload })).toString('base64url');
  message.signature.value = `${header}.${payload}.${Buffer.from(await otherSigner.signPreparedInput(new TextEncoder().encode(`${header}.${payload}`))).toString('base64url')}`;
  const egress = new RuntimeHostVerifier(other.did, otherSigner, resolvePeer, new ReplayCache());
  await egress.addVerifiedSession(validProof);
  const outbound = { envelope: { targetResourceDid: identity.did, sessionId: hello.body.sessionId, message }, audience: identity.did, requestId: 'request-1', payloadDigest: rawBodyDigest };
  await assert.rejects(egress.verifyOutbound({ ...outbound, audience: other.did }), /message_binding_mismatch/);
  await assert.rejects(egress.verifyOutbound({ ...outbound, payloadDigest: 'sha256:wrong' }), /message_binding_mismatch/);
  assert.equal((await egress.verifyOutbound(outbound)).subjectDid, other.did);
  await assert.rejects(egress.verifyOutbound(outbound), /replay_detected/);
  const scoped = new RuntimeHostVerifier(identity.did, signer, resolvePeer, new ReplayCache(), { runId: 'expected-run', tenantId: 'expected-tenant' });
  await scoped.addVerifiedSession({ scope, transcript: [hello, server, client, confirmation] });
  await assert.rejects(scoped.verify({ envelope: { targetResourceDid: identity.did, sessionId: hello.body.sessionId, message, tenantId: 'expected-tenant' }, audience: identity.did, requestId: 'request-1', payloadDigest: rawBodyDigest }), /message_binding_mismatch/);
  const oldExpiry = peers.get(other.did)!.validUntil;
  peers.get(other.did)!.validUntil = Date.now() - 1;
  await assert.rejects(host.verify({ envelope: { targetResourceDid: identity.did, sessionId: hello.body.sessionId, message }, audience: identity.did, requestId: 'request-1', payloadDigest: rawBodyDigest }), /session_evidence_expired/);
  peers.get(other.did)!.validUntil = oldExpiry;
  await independent.addVerifiedSession(validProof);
  await assert.rejects(independent.verify({ envelope: { targetResourceDid: identity.did, sessionId: hello.body.sessionId, message,
    tenantId: 'independent-tenant' }, audience: identity.did, requestId: 'request-1', payloadDigest: rawBodyDigest }), /message_binding_mismatch/);
  const contextual = structuredClone(message);
  contextual.payload = { rawBodyDigest, workspace: 'independent-workspace', tenantId: 'independent-tenant',
    httpBinding: { method: 'POST', target: '/native', mcpSessionId: '' } };
  contextual.context.payloadDigest = await digestJson(contextual.payload);
  const contextBytes = Buffer.from(canonicalJson({ context: contextual.context, operation: contextual.operation,
    serviceRef: contextual.serviceRef, protocolVersion: contextual.protocolVersion, payload: contextual.payload })).toString('base64url');
  contextual.signature.value = `${header}.${contextBytes}.${Buffer.from(await otherSigner.signPreparedInput(new TextEncoder().encode(`${header}.${contextBytes}`))).toString('base64url')}`;
  assert.equal((await independent.verify({ envelope: { targetResourceDid: identity.did, sessionId: hello.body.sessionId,
    message: contextual, tenantId: 'independent-tenant' }, audience: identity.did, requestId: 'request-1', payloadDigest: rawBodyDigest })).subjectDid, other.did);
  const result = await host.verify({ envelope: { targetResourceDid: identity.did, sessionId: hello.body.sessionId, message }, audience: identity.did, requestId: 'request-1', payloadDigest: rawBodyDigest });
  assert.equal(result.subjectDid, peer.did);
  const concurrent = structuredClone(message);
  concurrent.context.nonce = 'fresh-nonce-same-request';
  const concurrentPayload = Buffer.from(canonicalJson({ context: concurrent.context, operation: concurrent.operation, serviceRef: concurrent.serviceRef, protocolVersion: concurrent.protocolVersion, payload: concurrent.payload })).toString('base64url');
  concurrent.signature.value = `${header}.${concurrentPayload}.${Buffer.from(await otherSigner.signPreparedInput(new TextEncoder().encode(`${header}.${concurrentPayload}`))).toString('base64url')}`;
  await assert.rejects(host.verify({ envelope: { targetResourceDid: identity.did, sessionId: hello.body.sessionId, message: concurrent }, audience: identity.did, requestId: 'request-1', payloadDigest: rawBodyDigest }), /request_already_in_flight/);
  const responseBody = Buffer.from('real response');
  const { createHash } = await import('node:crypto');
  const encodedProof = Buffer.from(JSON.stringify(await host.sign({ kind: 'sidecar-response', requestId: 'request-1', requestPayloadDigest: rawBodyDigest,
    payloadDigest: `sha256:${createHash('sha256').update(responseBody).digest('hex')}`, targetResourceDid: identity.did, audienceDid: other.did, status: 200 }))).toString('base64url');
  const responseInput = { encodedProof, responseBody, status: 200, expected: { kind: 'sidecar-response' as const, requestId: 'request-1', requestPayloadDigest: rawBodyDigest, targetResourceDid: identity.did, audienceDid: other.did, senderDid: identity.did }, resolvePeer };
  await verifyNativeResponseProof(responseInput);
  for (const validUntil of [NaN, Date.now() - 1]) await assert.rejects(verifyNativeResponseProof({ ...responseInput, resolvePeer: async did => ({ ...await resolvePeer(did), validUntil }) }), /response_peer_evidence_invalid/);
  await assert.rejects(verifyNativeResponseProof({ ...responseInput, resolvePeer: async did => ({ ...await resolvePeer(did), did: other.did }) }), /response_peer_evidence_invalid/);
  await assert.rejects(host.verify({ envelope: { targetResourceDid: identity.did, sessionId: hello.body.sessionId, message }, audience: identity.did, requestId: 'request-1', payloadDigest: rawBodyDigest }), /replay_detected/);
  await assert.rejects(host.verify({ envelope: { targetResourceDid: identity.did, sessionId: hello.body.sessionId, message }, audience: identity.did, requestId: 'request-1', payloadDigest: `sha256:${'b'.repeat(64)}` }), /payload_digest_mismatch/);
});
