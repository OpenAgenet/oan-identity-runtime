// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJson, createJwkOanSigner, createOanIdentityRecord } from '@openagenet/oan-sdk-ts';
import { RuntimeHostVerifier } from '../src/host/runtime-host.js';
import { ReplayCache } from '../src/session/index.js';
import { MutualHandshake } from '../src/session/handshake.js';

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
  const rawBodyDigest = `sha256:${'a'.repeat(64)}`;
  const message = { context: { profile: 'oan-message-v1', senderDid: peer.did, audienceDid: identity.did, purpose: 'request', protocol: 'mcp', sessionId: hello.body.sessionId, messageId: 'm-1', requestId: 'request-1', nonce: 'nonce-1', createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 30000).toISOString(), payloadDigest: 'sha256:placeholder' }, operation: 'tools/call', serviceRef: scope.serviceRef, protocolVersion: '2025-11-25', payload: { rawBodyDigest }, signature: { verificationMethod: peer.verificationMethod, value: '' } } as any;
  const { digestJson } = await import('../src/verification/index.js');
  message.context.payloadDigest = await digestJson(message.payload);
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: peer.verificationMethod, typ: 'oan-message-v1+jws' })).toString('base64url');
  const payload = Buffer.from(canonicalJson({ context: message.context, operation: message.operation, serviceRef: message.serviceRef, protocolVersion: message.protocolVersion, payload: message.payload })).toString('base64url');
  message.signature.value = `${header}.${payload}.${Buffer.from(await otherSigner.signPreparedInput(new TextEncoder().encode(`${header}.${payload}`))).toString('base64url')}`;
  const result = await host.verify({ envelope: { targetResourceDid: identity.did, sessionId: hello.body.sessionId, message }, audience: identity.did, requestId: 'request-1', payloadDigest: rawBodyDigest });
  assert.equal(result.subjectDid, peer.did);
  await assert.rejects(host.verify({ envelope: { targetResourceDid: identity.did, sessionId: hello.body.sessionId, message }, audience: identity.did, requestId: 'request-1', payloadDigest: rawBodyDigest }), /replay_detected/);
  await assert.rejects(host.verify({ envelope: { targetResourceDid: identity.did, sessionId: hello.body.sessionId, message }, audience: identity.did, requestId: 'request-1', payloadDigest: `sha256:${'b'.repeat(64)}` }), /payload_digest_mismatch/);
});
